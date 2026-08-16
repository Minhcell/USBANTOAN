"""USB AN TOAN v9B - Sector truc tiep (giong H04)
Khong mount, khong hien o dia. Doc/ghi truc tiep sector."""
import sys,os,json,struct,hashlib,shutil,subprocess,tempfile,time,threading,ctypes,zipfile
from pathlib import Path;from datetime import datetime
from ctypes import wintypes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from PyQt5.QtWidgets import *;from PyQt5.QtCore import *;from PyQt5.QtGui import *

CF=".usbantoan";MG=b"USBAT90B";CK=1024*1024;SECTOR=512
APP="USB AN TOAN";VER="9B-Sector";USB_EXE="USB_AN_TOAN.exe";ADMIN="M@nh6868";PUB_MB=100
# Sector layout tren partition 2:
HDR_SEC=0;CFG_SEC=1;TBL_START=8;TBL_END=1032;DATA_START=1032;ENTRY_SZ=512;MAX_FILES=2048
SEC_MAGIC=b"SECVAULT"
# Chan MOI file copy truc tiep vao phan vung EXE (chi cho phep EXE + config)

def is_setup():return "setup" in os.path.basename(sys.argv[0]).lower()

# ══ CRYPTO ══
def dk(p,s):return PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=s,iterations=600000).derive(p.encode())
def hp(p,s):return hashlib.pbkdf2_hmac("sha256",p.encode(),s,600000)
def aes_enc(data,pw):
    sa=os.urandom(16);k=dk(pw,sa);a=AESGCM(k);nc=os.urandom(12)
    enc=a.encrypt(nc,data,None);return sa+nc+enc
def aes_dec(data,pw):
    sa=data[:16];nc=data[16:28];enc=data[28:]
    k=dk(pw,sa);a=AESGCM(k);return a.decrypt(nc,enc,None)

# ══ RAW DISK I/O (NO_BUFFERING de tranh Windows cache) ══
FILE_FLAG_NO_BUFFERING=0x20000000
FILE_FLAG_WRITE_THROUGH=0x80000000

def _aligned_buffer(size):
    """Tao buffer can chinh theo sector (dung VirtualAlloc)."""
    # VirtualAlloc tra ve memory can chinh 4096 (page) > 512 (sector)
    MEM_COMMIT=0x1000;MEM_RESERVE=0x2000;PAGE_READWRITE=0x04
    k32=ctypes.windll.kernel32
    k32.VirtualAlloc.restype=ctypes.c_void_p
    addr=k32.VirtualAlloc(None,size,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE)
    if not addr:raise OSError("VirtualAlloc fail")
    return addr

def _free_buffer(addr):
    MEM_RELEASE=0x8000
    ctypes.windll.kernel32.VirtualFree(ctypes.c_void_p(addr),0,MEM_RELEASE)

def disk_open(dn):
    k32=ctypes.windll.kernel32
    # NO_BUFFERING + WRITE_THROUGH -> bo qua cache Windows, ghi/doc truc tiep
    h=k32.CreateFileW(f"\\\\.\\PhysicalDrive{dn}",0xC0000000,3,None,3,
                      FILE_FLAG_NO_BUFFERING|FILE_FLAG_WRITE_THROUGH,None)
    if h==-1:raise OSError(f"Khong mo duoc disk {dn}! Can Admin.")
    return h
def disk_close(h):
    try:ctypes.windll.kernel32.FlushFileBuffers(h)
    except:pass
    ctypes.windll.kernel32.CloseHandle(h)
def disk_read(h,sector,count=1):
    k32=ctypes.windll.kernel32;off=sector*SECTOR;sz=count*SECTOR
    hi=ctypes.c_long(off>>32);k32.SetFilePointer(h,off&0xFFFFFFFF,ctypes.byref(hi),0)
    # Buffer can chinh cho NO_BUFFERING
    addr=_aligned_buffer(sz)
    try:
        rd=wintypes.DWORD(0)
        if not k32.ReadFile(h,ctypes.c_void_p(addr),sz,ctypes.byref(rd),None):
            raise OSError(f"Read fail sector {sector}: err {ctypes.windll.kernel32.GetLastError()}")
        return ctypes.string_at(addr,rd.value)
    finally:_free_buffer(addr)
def disk_write(h,sector,data):
    k32=ctypes.windll.kernel32;off=sector*SECTOR
    rem=len(data)%SECTOR
    if rem:data=data+b'\0'*(SECTOR-rem)
    hi=ctypes.c_long(off>>32);k32.SetFilePointer(h,off&0xFFFFFFFF,ctypes.byref(hi),0)
    # Copy data vao buffer can chinh
    addr=_aligned_buffer(len(data))
    try:
        ctypes.memmove(addr,data,len(data))
        wr=wintypes.DWORD(0)
        if not k32.WriteFile(h,ctypes.c_void_p(addr),len(data),ctypes.byref(wr),None):
            raise OSError(f"Write fail sector {sector}: err {ctypes.windll.kernel32.GetLastError()}")
        return wr.value
    finally:_free_buffer(addr)

def get_physical_drive_number(drive_letter):
    """Lay so PhysicalDrive that cua o dia (vd 'E:' -> 1) luc chay.
    Dung IOCTL_STORAGE_GET_DEVICE_NUMBER - CHINH XAC tren moi may."""
    try:
        letter=drive_letter.rstrip(":\\/")[0].upper()
        k32=ctypes.windll.kernel32
        # Mo volume \\.\E:
        h=k32.CreateFileW(f"\\\\.\\{letter}:",0,3,None,3,0,None)
        if h==-1:return -1
        try:
            IOCTL_STORAGE_GET_DEVICE_NUMBER=0x2D1080
            # STORAGE_DEVICE_NUMBER: DeviceType(4)+DeviceNumber(4)+PartitionNumber(4)
            buf=ctypes.create_string_buffer(12)
            ret=wintypes.DWORD(0)
            ok=k32.DeviceIoControl(h,IOCTL_STORAGE_GET_DEVICE_NUMBER,None,0,
                                    buf,12,ctypes.byref(ret),None)
            if ok:
                dev_type,dev_num,part_num=struct.unpack("<III",buf.raw[:12])
                return dev_num
        finally:k32.CloseHandle(h)
    except:pass
    return -1

def read_mbr_partition_offset(dn,part_index=2):
    """Doc MBR lay LBA start that cua partition (1-4)."""
    try:
        h=disk_open(dn)
        mbr=disk_read(h,0)
        disk_close(h)
        # Partition table tai byte 446, moi entry 16 byte
        entry_off=446+(part_index-1)*16
        entry=mbr[entry_off:entry_off+16]
        if len(entry)<16:return None
        # Byte 8-11 = LBA start (little endian)
        lba=struct.unpack("<I",entry[8:12])[0]
        # Byte 12-15 = so sector
        num=struct.unpack("<I",entry[12:16])[0]
        if lba>0 and num>0:return lba
        return None
    except:return None

def lock_volume(dn):
    """Khoa physical drive de ghi sector (tranh Windows chan)."""
    pass  # Physical drive khong can lock neu partition chua mount

def write_config_to_sector(dn,offset,cfg):
    """Ghi config vao vung du lieu (dung khi chua mo SectorFS, vd trong setup)."""
    h=disk_open(dn)
    try:
        data=json.dumps(cfg).encode()
        blob=struct.pack("<I",len(data))+data
        disk_write(h,offset+CFG_SEC,blob)
    finally:disk_close(h)

def read_config_from_sector(dn,offset):
    """Doc config tu vung du lieu (dung truoc khi mo SectorFS)."""
    try:
        h=disk_open(dn)
        try:
            raw=disk_read(h,offset+CFG_SEC,TBL_START-CFG_SEC)
            ln=struct.unpack("<I",raw[:4])[0]
            if ln<=0 or ln>len(raw)-4:return None
            return json.loads(raw[4:4+ln].decode())
        finally:disk_close(h)
    except:return None

def set_volume_readonly(letter,readonly=True):
    """Dat phan vung read-only bang diskpart (chan copy truc tiep vao)."""
    letter=letter.rstrip(":\\/")[0].upper()
    cmd="set"if readonly else"clear"
    _dp(f"select volume {letter}\nattributes volume {cmd} readonly\nexit\n")

# ══ SECTOR FILE SYSTEM ══
class SectorEntry:
    def __init__(s,name="",sec=0,sz=0,esz=0,act=True):
        s.name=name;s.sec=sec;s.sz=sz;s.esz=esz;s.act=act
    def pack(s):
        nb=s.name.encode('utf-8')[:455]
        nb=nb+b'\0'*(456-len(nb))
        # 456 + 8+8+8+4 = 484, pad 28 = 512
        return struct.pack('<456sQQQI28s',nb,s.sec,s.sz,s.esz,1 if s.act else 0,b'\0'*28)
    @staticmethod
    def unpack(d):
        nb,sec,sz,esz,fl,_=struct.unpack('<456sQQQI28s',d)
        nm=nb.split(b'\0')[0].decode('utf-8',errors='ignore')
        return SectorEntry(nm,sec,sz,esz,fl==1)

class USBGuard(QThread):
    """Chan MOI file/thu muc copy truc tiep vao phan vung EXE (khong qua app).
    Chi giu lai EXE + config. Xoa tat ca thu khac lien tuc."""
    alert=pyqtSignal(str)
    ALLOWED={CF,CF.lower(),USB_EXE,USB_EXE.lower(),"._sysfill","autorun.inf",
             "System Volume Information","$RECYCLE.BIN","desktop.ini","Thumbs.db"}
    def __init__(s,root):super().__init__();s.root=root;s._stop=False;s._count=0
    def stop(s):s._stop=True
    def run(s):
        while not s._stop:
            try:
                for n in os.listdir(s.root):
                    if s._stop:break
                    # Giu lai EXE, config va System Volume Information
                    if n in s.ALLOWED:continue
                    # Config an (.usbantoan) duoc giu, cac file . khac bi xoa
                    if n==CF:continue
                    fp=os.path.join(s.root,n)
                    try:
                        if os.path.isdir(fp):shutil.rmtree(fp,True)
                        else:
                            # Bo thuoc tinh read-only/hidden truoc khi xoa
                            try:ctypes.windll.kernel32.SetFileAttributesW(fp,0x80)
                            except:pass
                            os.remove(fp)
                        s._count+=1
                        s.alert.emit(f"Da xoa file copy truc tiep: '{n}' (chi copy qua app!)")
                    except:pass
            except:pass
            time.sleep(0.5)  # Quet nhanh hon (2 lan/giay)

class SectorFS:
    """File system truc tiep tren sector - KHONG mount."""
    def __init__(s,dn,part_offset):
        s.dn=dn;s.off=part_offset;s.h=None;s.files=[]
        s._max_tbl_sec=TBL_START  # sector table cao nhat da tung ghi
    def open(s):s.h=disk_open(s.dn);s._read_tbl()
    def close(s):
        if s.h:disk_close(s.h);s.h=None
    def _as(s,rs):return s.off+rs
    def _read_tbl(s):
        s.files=[];s._max_tbl_sec=TBL_START
        for sec in range(TBL_START,TBL_END):
            try:data=disk_read(s.h,s._as(sec))
            except:break
            found_in_sec=False
            for i in range(SECTOR//ENTRY_SZ):
                ed=data[i*ENTRY_SZ:(i+1)*ENTRY_SZ]
                if len(ed)<ENTRY_SZ or ed[:8]==b'\0'*8:continue
                try:
                    e=SectorEntry.unpack(ed)
                    if e.name and e.act:s.files.append(e);found_in_sec=True
                except:pass
            if found_in_sec:s._max_tbl_sec=sec
    def _write_tbl(s):
        """Ghi bang + XOA het sector table cu de tranh du entry."""
        # Chi giu file active
        active=[f for f in s.files if f.act]
        s.files=active
        idx=0;last_written=TBL_START
        for sec in range(TBL_START,TBL_END):
            sd=b''
            for i in range(SECTOR//ENTRY_SZ):
                if idx<len(active):sd+=active[idx].pack();idx+=1
                else:sd+=b'\0'*ENTRY_SZ
            disk_write(s.h,s._as(sec),sd)
            last_written=sec
            if idx>=len(active):break
        # XOA cac sector table cu con sot (tu last_written+1 den max cu)
        for sec in range(last_written+1,s._max_tbl_sec+1):
            disk_write(s.h,s._as(sec),b'\0'*SECTOR)
        s._max_tbl_sec=max(last_written,TBL_START)
    def list_files(s):return[(f.name,f.sz)for f in s.files if f.act]
    def _next_free_sector(s):
        """Tim sector trong ke tiep (tinh ca tat ca file active)."""
        if not s.files:return DATA_START
        return max(f.sec+((f.esz+SECTOR-1)//SECTOR)+4 for f in s.files if f.act)
    def write_file(s,name,enc_data):
        # Xoa file cung ten cu (neu co) truoc khi ghi moi
        s.files=[f for f in s.files if not(f.name==name and f.act)]
        last=s._next_free_sector()
        # Ghi data theo tung sector-aligned chunk
        total=len(enc_data);sec_written=0;pos=0
        while pos<total:
            chunk=enc_data[pos:pos+SECTOR*128]
            disk_write(s.h,s._as(last+sec_written),chunk)
            sec_written+=(len(chunk)+SECTOR-1)//SECTOR
            pos+=len(chunk)
        s.files.append(SectorEntry(name,last,len(enc_data),len(enc_data)))
        s._write_tbl()
        # Verify
        check=disk_read(s.h,s._as(last),1)
        return len(check)>0
    def read_file(s,name):
        for f in s.files:
            if f.name==name and f.act:
                sn=(f.esz+SECTOR-1)//SECTOR
                data=b'';read_sec=0
                while read_sec<sn:
                    cnt=min(128,sn-read_sec)
                    data+=disk_read(s.h,s._as(f.sec+read_sec),cnt)
                    read_sec+=cnt
                return data[:f.esz]
        return None
    def delete_file(s,name):
        # XOA HAN entry (khong giu inactive)
        s.files=[f for f in s.files if f.name!=name]
        s._write_tbl()
    def rebuild(s,files_data):
        """Xoa sach + ghi lai toan bo file (dung cho cep)."""
        # Xoa het bang cu
        for sec in range(TBL_START,s._max_tbl_sec+1):
            disk_write(s.h,s._as(sec),b'\0'*SECTOR)
        s.files=[]
        last=DATA_START
        for name,enc in files_data:
            total=len(enc);sec_written=0;pos=0
            while pos<total:
                chunk=enc[pos:pos+SECTOR*128]
                disk_write(s.h,s._as(last+sec_written),chunk)
                sec_written+=(len(chunk)+SECTOR-1)//SECTOR
                pos+=len(chunk)
            s.files.append(SectorEntry(name,last,total,total))
            last+=((total+SECTOR-1)//SECTOR)+4
        s._write_tbl()
    def get_used(s):return sum(f.esz for f in s.files if f.act)
    def write_config(s,cfg):
        """Ghi config vao vung du lieu (sector CFG_SEC) - raw sector, khong bi read-only chan."""
        data=json.dumps(cfg).encode()
        blob=struct.pack("<I",len(data))+data
        # Ghi toi da 7 sector (CFG_SEC den TBL_START-1)
        disk_write(s.h,s._as(CFG_SEC),blob)
    def read_config(s):
        """Doc config tu vung du lieu."""
        try:
            raw=disk_read(s.h,s._as(CFG_SEC),TBL_START-CFG_SEC)  # 7 sector
            ln=struct.unpack("<I",raw[:4])[0]
            if ln<=0 or ln>len(raw)-4:return None
            return json.loads(raw[4:4+ln].decode())
        except:return None

# ══ PARTITION HELPERS ══
def _dp(script):
    tf=tempfile.NamedTemporaryFile(mode='w',suffix='.txt',delete=False);tf.write(script);tf.close()
    try:return subprocess.run(["diskpart","/s",tf.name],capture_output=True,text=True,timeout=60,creationflags=0x08000000).stdout
    except Exception as e:return str(e)
    finally:
        try:os.unlink(tf.name)
        except:pass
def list_disks():
    out=_dp("list disk\n");disks=[]
    for l in out.split("\n"):
        l=l.strip()
        if l.lower().startswith("disk")and"---"not in l and"#"not in l.lower():
            p=l.split()
            if len(p)>=2:
                try:disks.append((int(p[1])," ".join(p[2:])))
                except:pass
    return disks
def get_part2_offset(dn):
    """Tim sector bat dau cua partition 2 tu MBR."""
    real=read_mbr_partition_offset(dn,2)
    if real:return real
    # Fallback: uoc luong
    return (PUB_MB*1024*1024)//SECTOR + 2048

def read_mbr_partition_size(dn,part_index=1):
    """Doc so sector cua partition tu MBR."""
    try:
        h=disk_open(dn);mbr=disk_read(h,0);disk_close(h)
        eo=446+(part_index-1)*16;entry=mbr[eo:eo+16]
        if len(entry)<16:return None
        lba=struct.unpack("<I",entry[8:12])[0]
        num=struct.unpack("<I",entry[12:16])[0]
        return (lba,num)if lba>0 else None
    except:return None

def setup_partitions(dn,pw,cb=None):
    if dn<=0:return False,"Disk khong hop le!"
    if cb:cb("Xoa USB...");_dp(f"select disk {dn}\nclean\nexit\n");time.sleep(2)
    # CHI tao 1 phan vung 64MB, PHAN CON LAI de UNALLOCATED
    # -> Windows KHONG thay, KHONG doi format vung du lieu
    if cb:cb("Tao phan vung EXE...")
    _dp(f"select disk {dn}\ncreate partition primary size={PUB_MB}\nformat fs=fat32 quick label=\"USB AN TOAN\"\nactive\nassign\nexit\n")
    time.sleep(3)
    # Vung du lieu = ngay sau partition 1 (trong vung unallocated)
    p1=read_mbr_partition_size(dn,1)
    if p1:
        p1_start,p1_num=p1
        data_off=p1_start+p1_num  # sector bat dau vung unallocated
    else:
        data_off=(PUB_MB*1024*1024)//SECTOR+2048
    # Ghi header vao vung du lieu (raw sector, khong phai partition)
    try:
        h=disk_open(dn)
        hdr=SEC_MAGIC+struct.pack("<I",0)+b'\0'*(SECTOR-12)
        disk_write(h,data_off,hdr)
        check=disk_read(h,data_off)
        disk_close(h)
        if check[:8]!=SEC_MAGIC:
            return False,f"Ghi sector that bai!\nOffset: {data_off}"
    except Exception as e:return False,f"Loi ghi header: {e}"
    if cb:cb("Tim phan vung EXE...")
    pub=None
    import ctypes as ct
    for _ in range(5):
        bm=ct.windll.kernel32.GetLogicalDrives()
        for i in range(26):
            if bm&(1<<i):
                d=chr(65+i)+":\\"
                try:
                    if ct.windll.kernel32.GetDriveTypeW(d)==2:
                        u=shutil.disk_usage(d)
                        if u.total<200*1024*1024:pub=d;break
                except:pass
        if pub:break
        time.sleep(2)
    if not pub:return False,"Khong tim phan vung EXE!"
    sa=os.urandom(16)
    cfg={"v":VER,"salt":sa.hex(),"pw_hash":hp(pw,sa).hex(),"att":5,"disk_number":dn,
         "part2_offset":data_off,"data_offset":data_off,"enc_salt":"","enc_hash":"","enc_set":False}
    # Ghi config vao VUNG DU LIEU (raw sector) - de phan vung EXE co the read-only
    try:write_config_to_sector(dn,data_off,cfg)
    except Exception as e:return False,f"Loi ghi config sector: {e}"
    # Marker nho tren phan vung EXE de nhan dien USB (chi 1 lan luc setup)
    cp=os.path.join(pub,CF)
    try:
        with open(cp,"w")as f:json.dump({"usb_marker":True,"data_offset":data_off},f)
        ct.windll.kernel32.SetFileAttributesW(cp,0x06)
    except:pass
    # Copy EXE truoc khi lap day
    exe=os.path.abspath(sys.argv[0])
    if not exe.endswith(".py"):
        try:shutil.copy2(exe,os.path.join(pub,USB_EXE))
        except:pass
    # LAP DAY phan vung EXE -> free = 0 byte -> Windows chan MOI copy ("khong du dung luong")
    if cb:cb("Khoa phan vung (lap day)...")
    try:
        filler=os.path.join(pub,"._sysfill")
        with open(filler,"wb")as f:
            chunk=b'\0'*(1024*1024)
            while True:
                f.write(chunk)  # ghi den khi day thi loi -> dung
    except OSError:pass  # Day roi - dung
    except:pass
    try:ct.windll.kernel32.SetFileAttributesW(os.path.join(pub,"._sysfill"),0x06)
    except:pass
    # Them read-only (lop bao ve thu 2)
    try:
        time.sleep(1);set_volume_readonly(pub,True)
    except:pass
    return True,(f"Thanh cong!\n\n"
        f"Phan vung EXE: {pub} ({PUB_MB}MB)\n"
        f"  - Da LAP DAY (0 byte trong) + read-only\n"
        f"  - KHONG the copy truc tiep vao (chi qua app)\n"
        f"Vung du lieu: UNALLOCATED - Windows KHONG thay\n\n"
        f"Rut USB, cam lai, chay {USB_EXE}")

# ══ CONFIG/UTILS ══
def _h(p):
    if sys.platform=="win32"and os.path.exists(p):
        try:ctypes.windll.kernel32.SetFileAttributesW(p,0x06)
        except:pass
def sc(b,c):
    p=os.path.join(b,CF)
    try:ctypes.windll.kernel32.SetFileAttributesW(p,0x80)
    except:pass
    try:
        with open(p,"w")as f:json.dump(c,f)
        _h(p)
    except:pass
def lc(b):
    p=os.path.join(b,CF)
    if not os.path.exists(p):return None
    try:
        try:ctypes.windll.kernel32.SetFileAttributesW(p,0x80)
        except:pass
        with open(p)as f:d=json.load(f)
        _h(p);return d
    except:return None
def vl(c,p):return hp(p,bytes.fromhex(c["salt"]))==bytes.fromhex(c["pw_hash"])
def ve(c,p):
    if not c.get("enc_salt"):return False
    return hp(p,bytes.fromhex(c["enc_salt"]))==bytes.fromhex(c["enc_hash"])
def gd():
    dr=[]
    try:
        bm=ctypes.windll.kernel32.GetLogicalDrives()
        for i in range(26):
            if bm&(1<<i):dr.append(chr(65+i)+":\\")
    except:dr=["C:\\"]
    return dr
def du():
    """Tim o dia USB (phan vung EXE) chua marker."""
    e=os.path.abspath(sys.argv[0]);d=os.path.dirname(e)
    for _ in range(5):
        if os.path.exists(os.path.join(d,CF)):return d
        p=os.path.dirname(d)
        if p==d:break
        d=p
    drv=os.path.splitdrive(e)[0]
    if drv and os.path.exists(os.path.join(drv+os.sep,CF)):return drv+os.sep
    return None
def fs(n):
    for u in["B","KB","MB","GB","TB"]:
        if n<1024:return f"{n:.0f}{u}"
        n/=1024
    return f"{n:.0f}PB"
def is_admin():
    try:return ctypes.windll.shell32.IsUserAnAdmin()!=0
    except:return False
def run_admin():
    try:ctypes.windll.shell32.ShellExecuteW(None,"runas",sys.argv[0],"",None,1);return True
    except:return False

S="""*{font-family:'Segoe UI';font-size:9px;}
QMainWindow,QDialog{background:#e8eef4;color:#1a2a3a;}QLabel{color:#3a4a5a;}
QWidget#tb{background:#d0dce8;border-bottom:1px solid #a0b0c0;}
QWidget#pnl{background:#f0f4f8;border:1px solid #c0ccd8;border-radius:4px;}
QPushButton{background:#dce4ee;border:1px solid #b0bcc8;border-radius:3px;padding:3px 8px;color:#2a3a4a;}
QPushButton:hover{background:#c8d4e2;}
QPushButton#bp{background:#d0d8e2;border:1px solid #a8b4c2;color:#2a3a4a;font-weight:bold;}
QPushButton#bs{background:#d0d8e2;border:1px solid #a8b4c2;color:#2a3a4a;font-weight:bold;}
QPushButton#bd{background:#d8d0d0;border:1px solid #c0b0b0;color:#2a3a4a;}
QTreeWidget{background:white;border:1px solid #c0ccd8;border-radius:3px;outline:none;alternate-background-color:#f4f6f9;}
QTreeWidget::item{padding:2px;}QTreeWidget::item:selected{background:#bbdefb;color:#0d47a1;}
QHeaderView::section{background:#e0e8f0;color:#4a5a6a;border:none;border-bottom:1px solid #c0ccd8;padding:3px 4px;font-size:8px;}
QComboBox{background:white;border:1px solid #c0ccd8;border-radius:3px;padding:2px 6px;}
QProgressBar{background:#e0e8f0;border:1px solid #c0ccd8;border-radius:2px;height:14px;text-align:center;font-size:8px;}
QProgressBar::chunk{background:#1565c0;}
QLineEdit{background:white;border:1px solid #b0bcc8;border-radius:3px;padding:5px 8px;font-size:10px;}
QLineEdit:focus{border-color:#1565c0;}QCheckBox{color:#5a6a7a;font-size:8px;}
QStatusBar{background:#d0dce8;color:#4a5a6a;border-top:1px solid #b0c0d0;font-size:8px;}"""

class PwD(QDialog):
    def __init__(s,title,msg,cfg=None,mode="login",parent=None):
        super().__init__(parent);s.cfg=cfg;s.password="";s.mode=mode
        s.setWindowTitle(title);s.setFixedSize(300,210);s.setStyleSheet(S)
        L=QVBoxLayout(s);L.setContentsMargins(20,10,20,10);L.setSpacing(4)
        L.addWidget(QLabel(APP,styleSheet="font-size:16px;font-weight:bold;color:#1565c0;",alignment=Qt.AlignCenter))
        if msg:L.addWidget(QLabel(msg,styleSheet="font-size:9px;color:#5a6a7a;",alignment=Qt.AlignCenter,wordWrap=True))
        s.pw=QLineEdit();s.pw.setPlaceholderText("Mat khau...");s.pw.setEchoMode(QLineEdit.Password);s.pw.returnPressed.connect(s.ck);L.addWidget(s.pw)
        sh=QCheckBox("Hien");sh.toggled.connect(lambda c:s.pw.setEchoMode(QLineEdit.Normal if c else QLineEdit.Password));L.addWidget(sh)
        if cfg and mode=="login":s.al=QLabel(f"Con {cfg.get('att',5)} lan",alignment=Qt.AlignCenter);L.addWidget(s.al)
        s.er=QLabel("",styleSheet="color:#e53935;");L.addWidget(s.er)
        r=QHBoxLayout();r.addWidget(QPushButton("Thoat",clicked=s.reject))
        b=QPushButton("MO KHOA");b.setObjectName("bp");b.clicked.connect(s.ck);r.addWidget(b);L.addLayout(r);s.pw.setFocus()
    def ck(s):
        pw=s.pw.text().strip()
        if not pw:return
        if s.mode=="login"and s.cfg:
            if vl(s.cfg,pw):s.cfg["att"]=5;s.password=pw;s.accept()
            else:
                a=s.cfg.get("att",5)-1;s.cfg["att"]=a
                if a<=0:QMessageBox.critical(s,"","Khoa!");s.reject()
                else:s.al.setText(f"SAI! Con {a}");s.pw.clear()
        elif s.mode=="enc"and s.cfg:
            if ve(s.cfg,pw):s.password=pw;s.accept()
            else:s.er.setText("Sai!");s.pw.clear()
        else:s.password=pw;s.accept()

class SetEP(QDialog):
    def __init__(s,p=None):
        super().__init__(p);s.setWindowTitle("MK ma hoa");s.setFixedSize(300,170);s.setStyleSheet(S);s.np=""
        L=QVBoxLayout(s);L.setContentsMargins(20,10,20,10);L.setSpacing(4)
        L.addWidget(QLabel("DAT MAT KHAU MA HOA"))
        s.e1=QLineEdit();s.e1.setEchoMode(QLineEdit.Password);L.addWidget(s.e1)
        s.e2=QLineEdit();s.e2.setEchoMode(QLineEdit.Password);s.e2.setPlaceholderText("Nhap lai");L.addWidget(s.e2)
        s.er=QLabel("",styleSheet="color:#e53935;");L.addWidget(s.er)
        r=QHBoxLayout();r.addWidget(QPushButton("Huy",clicked=s.reject))
        b=QPushButton("LUU");b.setObjectName("bp");b.clicked.connect(s.sv);r.addWidget(b);L.addLayout(r)
    def sv(s):
        if not s.e1.text():s.er.setText("Nhap!");return
        if s.e1.text()!=s.e2.text():s.er.setText("Khong khop!");return
        s.np=s.e1.text();s.accept()

# ══ SETUP ══
class SetupWin(QMainWindow):
    def __init__(s):
        super().__init__();s.setWindowTitle(f"{APP} Setup (Sector)");s.setFixedSize(440,380);s.setStyleSheet(S)
        c=QWidget();s.setCentralWidget(c);L=QVBoxLayout(c);L.setContentsMargins(20,12,20,12);L.setSpacing(5)
        L.addWidget(QLabel(f"{APP} Setup",styleSheet="font-size:16px;font-weight:bold;color:#1565c0;",alignment=Qt.AlignCenter))
        L.addWidget(QLabel("CACH B: Sector truc tiep (giong H04)\nKhong mount, khong hien o dia",styleSheet="color:#e65100;"))
        L.addWidget(QLabel("Chon USB:"));s.cb=QComboBox();L.addWidget(s.cb)
        rb=QPushButton("Lam moi");rb.clicked.connect(s.rf);L.addWidget(rb)
        L.addWidget(QLabel("MK dang nhap (>=6):"))
        s.p1=QLineEdit();s.p1.setEchoMode(QLineEdit.Password);L.addWidget(s.p1)
        s.p2=QLineEdit();s.p2.setEchoMode(QLineEdit.Password);s.p2.setPlaceholderText("Nhap lai");L.addWidget(s.p2)
        s.er=QLabel("",styleSheet="color:#e53935;");L.addWidget(s.er)
        s.st=QLabel("");L.addWidget(s.st);L.addStretch()
        b1=QPushButton("KHOI TAO");b1.setObjectName("bs");b1.setMinimumHeight(28);b1.clicked.connect(s.go);L.addWidget(b1)
        s.rf()
    def rf(s):
        s.cb.clear()
        for n,sz in list_disks():
            if n==0:continue
            s.cb.addItem(f"Disk {n} - {sz}",n)
    def go(s):
        dn=s.cb.currentData()
        if not dn or dn<1:s.er.setText("Chon!");return
        pw=s.p1.text()
        if len(pw)<6:s.er.setText(">=6!");return
        if pw!=s.p2.text():s.er.setText("Khong khop!");return
        if QMessageBox.warning(s,"",f"XOA Disk {dn}?",QMessageBox.Yes|QMessageBox.No)!=QMessageBox.Yes:return
        ok,msg=setup_partitions(dn,pw,lambda m:(s.st.setText(m),QApplication.processEvents()))
        if ok:QMessageBox.information(s,"OK",msg)
        else:QMessageBox.critical(s,"LOI",msg)
        s.rf()

# ══ MAIN WINDOW (Sector) ══
class MW(QMainWindow):
    def __init__(s,pub,pw,cfg):
        super().__init__();s.pub=pub;s.cfg=cfg;s.ep=""
        # QUAN TRONG: Tu nhan so disk cua USB LUC CHAY
        s.dn=get_physical_drive_number(pub)
        if s.dn<0:s.dn=cfg.get("disk_number",-1)
        # Vung du lieu = ngay sau partition 1 (unallocated). Doc tu MBR.
        p1=read_mbr_partition_size(s.dn,1)
        if p1:
            p1_start,p1_num=p1
            s.p2off=p1_start+p1_num
        else:
            s.p2off=cfg.get("data_offset",cfg.get("part2_offset",0))
        s.sfs=None;s.cp=str(Path.home());s._t=[]
        s.setWindowTitle(f"{APP} {VER}");s.setFixedSize(580,440);s.setStyleSheet(S)
        # Mo sector file system
        try:s.sfs=SectorFS(s.dn,s.p2off);s.sfs.open()
        except Exception as e:QMessageBox.critical(None,"",f"Loi mo disk {s.dn}: {e}")
        s.build();s.lpc(s.cp);s.luc();s.us()
        # Chan copy truc tiep vao phan vung EXE (khong qua app)
        s.guard=USBGuard(s.pub)
        s.guard.alert.connect(lambda m:s.statusBar().showMessage(m,3000))
        s.guard.start()
        if not cfg.get("enc_set"):QTimer.singleShot(200,s.sep)

    def sep(s):
        QMessageBox.information(s,"","Dat MK ma hoa!")
        d=SetEP(s)
        if d.exec_()==QDialog.Accepted:
            s.ep=d.np;sa=os.urandom(16);s.cfg["enc_salt"]=sa.hex();s.cfg["enc_hash"]=hp(d.np,sa).hex();s.cfg["enc_set"]=True;s.sfs.write_config(s.cfg)

    def build(s):
        s.usb_path=""  # duong dan thu muc ao hien tai trong USB
        cw=QWidget();s.setCentralWidget(cw);rt=QVBoxLayout(cw);rt.setContentsMargins(0,0,0,0);rt.setSpacing(0)
        tb=QWidget();tb.setObjectName("tb");tb.setFixedHeight(26)
        tl=QHBoxLayout(tb);tl.setContentsMargins(6,0,6,0);tl.setSpacing(3)
        tl.addWidget(QLabel(f"{APP} (Sector)",styleSheet="font-size:10px;font-weight:bold;color:#0d47a1;"))
        s.ls=QLabel("",styleSheet="font-size:8px;color:#4a6a8a;");tl.addWidget(s.ls);tl.addStretch()
        for t,f in[("MK ma hoa",s.sep),("Doi MK ma hoa",s.cep),("Doi MK DN",s.clp)]:
            b=QPushButton(t);b.setFixedHeight(18);b.clicked.connect(f);tl.addWidget(b)
        bl=QPushButton("Thoat");bl.setFixedHeight(18);bl.clicked.connect(s.close);tl.addWidget(bl)
        rt.addWidget(tb)
        bd=QWidget();bl_=QHBoxLayout(bd);bl_.setContentsMargins(3,3,3,3);bl_.setSpacing(0)
        # PC
        pc=QWidget();pc.setObjectName("pnl");pl=QVBoxLayout(pc);pl.setContentsMargins(3,3,3,3);pl.setSpacing(2)
        h1=QHBoxLayout();h1.addWidget(QLabel("MAY TINH"))
        s.cd=QComboBox();s.cd.setFixedHeight(18)
        for d in gd():s.cd.addItem(d,d)
        s.cd.currentIndexChanged.connect(lambda:s.lpc(s.cd.currentData()));h1.addWidget(s.cd)
        bu=QPushButton(" Len ");bu.setFixedSize(40,20);bu.clicked.connect(s.pu);h1.addWidget(bu)
        bnp=QPushButton("Thu muc");bnp.setFixedSize(52,20);bnp.clicked.connect(s.mk_pc_folder);h1.addWidget(bnp)
        pl.addLayout(h1)
        s.plb=QLabel("",styleSheet="font-size:8px;color:#5a7a9a;background:#e0e8f0;padding:1px 3px;");pl.addWidget(s.plb)
        s.tp=QTreeWidget();s.tp.setHeaderLabels(["Ten","Size","Ngay"]);s.tp.setAlternatingRowColors(True)
        s.tp.setSelectionMode(QAbstractItemView.ExtendedSelection);s.tp.setRootIsDecorated(False)
        s.tp.header().setSectionResizeMode(0,QHeaderView.Stretch);s.tp.setColumnWidth(1,50);s.tp.setColumnWidth(2,75)
        s.tp.itemDoubleClicked.connect(s.pdbl);pl.addWidget(s.tp);bl_.addWidget(pc,stretch=1)
        # Center - nut mau xam nhat, khong do mau
        ct=QWidget();ct.setFixedWidth(64);cl=QVBoxLayout(ct);cl.setContentsMargins(1,0,1,0);cl.setSpacing(3)
        GRAY="QPushButton{background:#dce4ee;border:1px solid #b0bcc8;color:#2a3a4a;font-weight:bold;border-radius:4px;}QPushButton:hover{background:#c8d4e2;}"
        cl.addStretch(2);cl.addWidget(QLabel("Ma hoa\nCopy",alignment=Qt.AlignCenter,styleSheet="font-size:7px;color:#5a6a7a;"))
        b1=QPushButton(">>>");b1.setFixedSize(58,32);b1.setStyleSheet(GRAY.replace("font-weight:bold;","font-size:15px;font-weight:bold;"))
        b1.clicked.connect(s.c2u);cl.addWidget(b1,alignment=Qt.AlignCenter);cl.addSpacing(8)
        b2=QPushButton("<<<");b2.setFixedSize(58,32);b2.setStyleSheet(GRAY.replace("font-weight:bold;","font-size:15px;font-weight:bold;"))
        b2.clicked.connect(s.cfu);cl.addWidget(b2,alignment=Qt.AlignCenter)
        cl.addWidget(QLabel("Giai ma\nCopy",alignment=Qt.AlignCenter,styleSheet="font-size:7px;color:#5a6a7a;"));cl.addSpacing(12)
        b3=QPushButton("Mo file");b3.setFixedSize(58,26);b3.setStyleSheet(GRAY.replace("font-weight:bold;","font-size:9px;font-weight:bold;"))
        b3.clicked.connect(s.of);cl.addWidget(b3,alignment=Qt.AlignCenter);cl.addSpacing(4)
        b4=QPushButton("Xoa");b4.setFixedSize(58,22);b4.setStyleSheet(GRAY.replace("font-weight:bold;","font-size:9px;font-weight:bold;"))
        b4.clicked.connect(s.ud);cl.addWidget(b4,alignment=Qt.AlignCenter);cl.addStretch(2);bl_.addWidget(ct)
        # USB (sector) - co thu muc ao
        ub=QWidget();ub.setObjectName("pnl");ul=QVBoxLayout(ub);ul.setContentsMargins(3,3,3,3);ul.setSpacing(2)
        h2=QHBoxLayout();h2.addWidget(QLabel("USB AN TOAN"));h2.addStretch()
        buu=QPushButton(" Len ");buu.setFixedSize(40,20);buu.clicked.connect(s.usb_up);h2.addWidget(buu)
        bnu=QPushButton("Thu muc");bnu.setFixedSize(52,20);bnu.clicked.connect(s.mk_usb_folder);h2.addWidget(bnu)
        ul.addLayout(h2)
        s.ulb=QLabel("",styleSheet="font-size:8px;color:#5a7a9a;background:#e0e8f0;padding:1px 3px;");ul.addWidget(s.ulb)
        s.tu=QTreeWidget();s.tu.setHeaderLabels(["Ten","Size"]);s.tu.setAlternatingRowColors(True)
        s.tu.setSelectionMode(QAbstractItemView.ExtendedSelection);s.tu.setRootIsDecorated(False)
        s.tu.header().setSectionResizeMode(0,QHeaderView.Stretch);s.tu.setColumnWidth(1,70)
        s.tu.itemDoubleClicked.connect(s.udbl);ul.addWidget(s.tu);bl_.addWidget(ub,stretch=1)
        rt.addWidget(bd,stretch=1)
        s.pb=QProgressBar();s.pb.setVisible(False);s.pb.setTextVisible(True);rt.addWidget(s.pb)
        s.statusBar().showMessage("Cach B: Sector | Copy file+thu muc+file lon | Khong hien o dia")

    def _mt(s,fp):
        try:return datetime.fromtimestamp(os.path.getmtime(fp)).strftime("%d/%m/%y %H:%M")
        except:return""
    def lpc(s,p):
        s.tp.clear();s.cp=p;s.plb.setText(p)
        try:es=os.listdir(p)
        except:return
        ds,fl=[],[]
        for n in es:
            if n.startswith("."):continue
            fp=os.path.join(p,n)
            try:
                if os.path.isdir(fp):ds.append((n,fp))
                else:fl.append((n,fp))
            except:pass
        ds.sort(key=lambda x:x[0].lower());fl.sort(key=lambda x:x[0].lower())
        for n,fp in ds:
            it=QTreeWidgetItem([n,""]);it.setData(0,Qt.UserRole,fp);it.setData(0,Qt.UserRole+1,True)
            it.setIcon(0,s.style().standardIcon(QStyle.SP_DirIcon));s.tp.addTopLevelItem(it)
        for n,fp in fl:
            try:sz=os.path.getsize(fp)
            except:sz=0
            it=QTreeWidgetItem([n,fs(sz)]);it.setData(0,Qt.UserRole,fp);it.setData(0,Qt.UserRole+1,False)
            it.setIcon(0,s.style().standardIcon(QStyle.SP_FileIcon));s.tp.addTopLevelItem(it)
    def pdbl(s,it,c):
        fp=it.data(0,Qt.UserRole)
        if fp and it.data(0,Qt.UserRole+1):s.lpc(fp)
    def pu(s):
        p=os.path.dirname(s.cp)
        if p and p!=s.cp:s.lpc(p)
    def mk_pc_folder(s):
        n,ok=QInputDialog.getText(s,"Tao thu muc PC","Ten thu muc moi:")
        if ok and n.strip():
            try:os.makedirs(os.path.join(s.cp,n.strip()),exist_ok=True);s.lpc(s.cp)
            except Exception as e:QMessageBox.critical(s,"",f"Loi: {e}")
    def luc(s):
        """Load danh sach USB theo thu muc ao hien tai (usb_path)."""
        s.tu.clear()
        if not s.sfs:return
        s.sfs._read_tbl()
        prefix=s.usb_path
        s.ulb.setText(f"USB:/{prefix}"if prefix else"USB:/ (goc)")
        all_files=s.sfs.list_files()
        subfolders=set();files_here=[]
        for name,sz in all_files:
            if name.endswith("/.keep"):
                # File danh dau thu muc - dung de hien thu muc, khong hien file
                rel_marker=name[:-6]  # bo "/.keep"
                if prefix:
                    if rel_marker.startswith(prefix+"/"):
                        sub=rel_marker[len(prefix)+1:]
                        if "/" not in sub:subfolders.add(sub)
                else:
                    if "/" not in rel_marker:subfolders.add(rel_marker)
                continue
            if prefix:
                if not name.startswith(prefix+"/"):continue
                rest=name[len(prefix)+1:]
            else:
                rest=name
            if "/" in rest:
                subfolders.add(rest.split("/")[0])
            else:
                files_here.append((rest,name,sz))
        # Hien thu muc con truoc
        for fold in sorted(subfolders):
            it=QTreeWidgetItem([fold,"<thu muc>"]);it.setData(0,Qt.UserRole,fold);it.setData(0,Qt.UserRole+1,True)
            it.setIcon(0,s.style().standardIcon(QStyle.SP_DirIcon));s.tu.addTopLevelItem(it)
        # Roi den file
        for disp,fullname,sz in sorted(files_here):
            it=QTreeWidgetItem([disp,fs(sz)]);it.setData(0,Qt.UserRole,fullname);it.setData(0,Qt.UserRole+1,False)
            it.setIcon(0,s.style().standardIcon(QStyle.SP_FileIcon));s.tu.addTopLevelItem(it)
        s.us()
    def usb_up(s):
        if s.usb_path:
            s.usb_path="/".join(s.usb_path.split("/")[:-1])
            s.luc()
    def mk_usb_folder(s):
        n,ok=QInputDialog.getText(s,"Tao thu muc USB","Ten thu muc moi:")
        if not ok or not n.strip():return
        n=n.strip().replace("/","_").replace("\\","_")
        # Tao thu muc ao bang 1 file danh dau an (.keep)
        marker=(s.usb_path+"/"if s.usb_path else"")+n+"/.keep"
        pw=s._gep()
        if not pw:return
        try:
            s.sfs.write_file(marker,aes_enc(b"",pw))
            s.luc()
        except Exception as e:QMessageBox.critical(s,"",f"Loi: {e}")
    def udbl(s,it,c):
        name=it.data(0,Qt.UserRole)
        is_folder=it.data(0,Qt.UserRole+1)
        if is_folder:
            # Vao thu muc con
            s.usb_path=(s.usb_path+"/"if s.usb_path else"")+name
            s.luc()
        elif name:s._open(name)
    def _aep(s):
        d=PwD("Giai ma","MK ma hoa",s.cfg,"enc",s)
        return d.password if d.exec_()==QDialog.Accepted else None
    def _gep(s):
        if not s.cfg.get("enc_set"):QMessageBox.warning(s,"","Dat MK!");return None
        if s.ep:return s.ep
        d=PwD("Ma hoa","MK ma hoa",s.cfg,"enc",s)
        if d.exec_()==QDialog.Accepted:s.ep=d.password;return d.password
        return None
    def _open(s,name):
        pw=s._aep()
        if not pw or not s.sfs:return
        data=s.sfs.read_file(name)
        if not data:QMessageBox.critical(s,"","Khong doc duoc!");return
        try:
            dec=aes_dec(data,pw);del data
            tmp=tempfile.mkdtemp(prefix="usbat_")
            out=os.path.join(tmp,os.path.basename(name))
            with open(out,"wb")as f:f.write(dec)
            s._t.append(tmp)
            if sys.platform=="win32":os.startfile(out)
            else:subprocess.Popen(["xdg-open",out])
        except:QMessageBox.critical(s,"","Sai MK!")
    def of(s):
        for it in s.tu.selectedItems():
            name=it.data(0,Qt.UserRole)
            if name:s._open(name);break
    def c2u(s):
        sl=s.tp.selectedItems()
        if not sl or not s.sfs:return
        pw=s._gep()
        if not pw:return
        prefix=(s.usb_path+"/")if s.usb_path else ""
        # Thu thap file: (duong_dan_that, ten_luu_tren_usb)
        # File don le -> 1 file. Thu muc -> tao thu muc ao that (cac file ben trong)
        items=[]
        for it in sl:
            fp=it.data(0,Qt.UserRole)
            if not fp:continue
            if it.data(0,Qt.UserRole+1):
                # Thu muc -> luu tung file voi duong dan tuong doi (thu muc ao that)
                folder_base=os.path.dirname(fp)
                for root,_,files in os.walk(fp):
                    for fn in files:
                        full=os.path.join(root,fn)
                        rel=os.path.relpath(full,folder_base).replace("\\","/")
                        items.append((full,prefix+rel))
                # Neu thu muc rong, tao marker de van hien thu muc
                if not any(True for _,_,fs_ in os.walk(fp) for _ in fs_):
                    items.append((None,prefix+os.path.basename(fp)+"/.keep"))
            else:
                items.append((fp,prefix+os.path.basename(fp)))
        if not items:QMessageBox.information(s,"","Khong co gi de copy!");return
        s.pb.setVisible(True);ok_count=0
        for i,(full,name) in enumerate(items):
            s.pb.setFormat(f"[{i+1}/{len(items)}] {name}");s.pb.setValue(int(i/len(items)*100));QApplication.processEvents()
            try:
                if full is None:
                    # Marker thu muc rong
                    s.sfs.write_file(name,aes_enc(b"",pw))
                else:
                    sz=os.path.getsize(full)
                    s.pb.setFormat(f"[{i+1}/{len(items)}] {name} ({fs(sz)})");QApplication.processEvents()
                    with open(full,"rb")as f:data=f.read()
                    enc=aes_enc(data,pw);del data
                    s.sfs.write_file(name,enc);del enc
                ok_count+=1
            except MemoryError:
                QMessageBox.critical(s,"",f"File qua lon, thieu RAM: {name}")
            except Exception as e:QMessageBox.critical(s,"",f"Loi {name}: {e}")
        s.pb.setValue(100);QTimer.singleShot(2000,lambda:s.pb.setVisible(False))
        s.luc();QMessageBox.information(s,"",f"Da ma hoa {ok_count}/{len(items)} file vao USB!")
    def cfu(s):
        sl=s.tu.selectedItems()
        if not sl or not s.sfs:return
        pw=s._aep()
        if not pw:return
        # Neu chon thu muc ao -> giai ma tat ca file trong do
        names=[]
        for it in sl:
            nm=it.data(0,Qt.UserRole);is_folder=it.data(0,Qt.UserRole+1)
            if is_folder:
                # Lay tat ca file trong thu muc ao nay
                fold_prefix=((s.usb_path+"/")if s.usb_path else"")+nm+"/"
                for fn,_ in s.sfs.list_files():
                    if fn.startswith(fold_prefix)and not fn.endswith("/.keep"):names.append(fn)
            elif nm:names.append(nm)
        if not names:QMessageBox.information(s,"","Khong co file!");return
        s.pb.setVisible(True);ok_count=0
        for i,name in enumerate(names):
            s.pb.setFormat(f"[{i+1}/{len(names)}] {name}");s.pb.setValue(int(i/len(names)*100));QApplication.processEvents()
            data=s.sfs.read_file(name)
            if not data:continue
            try:
                dec=aes_dec(data,pw);del data
                # Bo tien to duong dan ao, chi lay ten file (hoac giu cau truc thu muc)
                rel=name
                out=os.path.join(s.cp,rel.replace("/",os.sep))
                d=os.path.dirname(out)
                if d:os.makedirs(d,exist_ok=True)
                b,e=os.path.splitext(out);c=1
                while os.path.exists(out):out=f"{b}({c}){e}";c+=1
                with open(out,"wb")as f:f.write(dec)
                del dec;ok_count+=1
            except:QMessageBox.critical(s,"","Sai MK!");s.pb.setVisible(False);return
        s.pb.setValue(100);QTimer.singleShot(2000,lambda:s.pb.setVisible(False))
        s.lpc(s.cp);QMessageBox.information(s,"",f"Da giai ma {ok_count} muc!\n(File .zip la thu muc - giai nen de dung)")
    def ud(s):
        sl=s.tu.selectedItems()
        if not sl or not s.sfs:return
        if QMessageBox.warning(s,"",f"Xoa {len(sl)} muc?",QMessageBox.Yes|QMessageBox.No)!=QMessageBox.Yes:return
        for it in sl:
            name=it.data(0,Qt.UserRole);is_folder=it.data(0,Qt.UserRole+1)
            if is_folder:
                # Xoa tat ca file trong thu muc ao
                fold_prefix=((s.usb_path+"/")if s.usb_path else"")+name+"/"
                for fn,_ in list(s.sfs.list_files()):
                    if fn.startswith(fold_prefix):s.sfs.delete_file(fn)
            elif name:s.sfs.delete_file(name)
        s.luc()
    def cep(s):
        if not s.cfg.get("enc_set"):QMessageBox.warning(s,"","Chua dat MK ma hoa!");return
        if not s.sfs:return
        apw,ok=QInputDialog.getText(s,"ADMIN","MK Admin:",QLineEdit.Password)
        if not ok:return
        if apw!=ADMIN:QMessageBox.critical(s,"","Sai Admin!");return
        old=s._aep()
        if not old:return
        npw,ok=QInputDialog.getText(s,"","MK ma hoa MOI:",QLineEdit.Password)
        if not ok or not npw:return
        npw2,ok=QInputDialog.getText(s,"","Nhap lai MK moi:",QLineEdit.Password)
        if not ok or npw!=npw2:QMessageBox.warning(s,"","Khong khop!");return
        s.pb.setVisible(True)
        files=s.sfs.list_files()
        new_data=[]
        for i,(name,_) in enumerate(files):
            s.pb.setValue(int(i/max(len(files),1)*100));QApplication.processEvents()
            data=s.sfs.read_file(name)
            if not data:continue
            try:
                dec=aes_dec(data,old);del data
                new_data.append((name,aes_enc(dec,npw)));del dec
            except:
                QMessageBox.critical(s,"","Sai MK cu!");s.pb.setVisible(False);return
        s.sfs.rebuild(new_data)
        s.pb.setValue(100);QTimer.singleShot(1500,lambda:s.pb.setVisible(False))
        sa=os.urandom(16);s.cfg["enc_salt"]=sa.hex();s.cfg["enc_hash"]=hp(npw,sa).hex()
        s.sfs.write_config(s.cfg);s.ep=npw
        s.luc();QMessageBox.information(s,"",f"Doi MK ma hoa thanh cong!\nDa ma hoa lai {len(new_data)} file.")
    def clp(s):
        d1=PwD("","MK cu",s.cfg,"login",s)
        if d1.exec_()!=QDialog.Accepted:return
        pw,ok=QInputDialog.getText(s,"","MK moi (>=6):",QLineEdit.Password)
        if not ok or len(pw)<6:return
        sa=os.urandom(16);s.cfg["salt"]=sa.hex();s.cfg["pw_hash"]=hp(pw,sa).hex();s.cfg["att"]=5;s.sfs.write_config(s.cfg)
        QMessageBox.information(s,"","Doi MK thanh cong!")
    def us(s):
        if s.sfs:s.ls.setText(f"Du lieu: {fs(s.sfs.get_used())} | Sector truc tiep")
    def closeEvent(s,ev):
        if hasattr(s,'guard'):s.guard.stop()
        try:
            if s.sfs:s.sfs.write_config(s.cfg)
        except:pass
        if s.sfs:s.sfs.close()
        for t in s._t:shutil.rmtree(t,True)
        ev.accept()  # Thoat NGAY LAP TUC

def main():
    if not is_setup() and not is_admin():
        if run_admin():sys.exit(0)
    if hasattr(Qt,'AA_EnableHighDpiScaling'):QApplication.setAttribute(Qt.AA_EnableHighDpiScaling,True)
    app=QApplication(sys.argv);app.setApplicationName(APP)
    if is_setup():
        if not is_admin():QMessageBox.warning(None,"","Can Admin!")
        w=SetupWin();w.show()
    else:
        up=du()
        if not up:QMessageBox.critical(None,"","Khong tim USB!");sys.exit(1)
        # Nhan dien disk + offset, doc config tu VUNG DU LIEU (raw sector)
        dn=get_physical_drive_number(up)
        if dn<0:
            # fallback: doc data_offset tu marker
            m=lc(up);dn=m.get("disk_number",-1)if m else -1
        p1=read_mbr_partition_size(dn,1)
        offset=(p1[0]+p1[1])if p1 else 0
        cfg=read_config_from_sector(dn,offset)
        if not cfg:
            # fallback: doc tu marker file cu (tuong thich nguoc)
            cfg=lc(up)
        if not cfg or "pw_hash" not in cfg:
            QMessageBox.critical(None,"","Chua khoi tao dung!\nChay Setup lai.");sys.exit(1)
        d=PwD("Dang nhap","MK dang nhap",cfg,"login")
        if d.exec_()==QDialog.Accepted:
            w=MW(up,d.password,cfg);w.show()
        else:sys.exit(0)
    sys.exit(app.exec_())

if __name__=="__main__":main()
