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

def get_disk_length_bytes(dn):
    """Lay tong dung luong disk (bytes) qua IOCTL_DISK_GET_LENGTH_INFO."""
    if sys.platform!="win32":return 0
    try:
        k32=ctypes.windll.kernel32
        h=k32.CreateFileW(f"\\\\.\\PhysicalDrive{dn}",0x80000000,3,None,3,0,None)
        if h==-1:return 0
        try:
            IOCTL_DISK_GET_LENGTH_INFO=0x0007405C
            buf=ctypes.create_string_buffer(8);rd=wintypes.DWORD(0)
            ok=k32.DeviceIoControl(h,IOCTL_DISK_GET_LENGTH_INFO,None,0,buf,8,ctypes.byref(rd),None)
            if ok:return struct.unpack("<q",buf.raw[:8])[0]
        finally:k32.CloseHandle(h)
    except:pass
    return 0

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
                    # Giu TAT CA file lap day (._sysfill, ._sysfill2, ._sysfill_tailN...)
                    if n.startswith("._sysfill"):continue
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

    def write_file_stream(s,name,src_path,pw,progress=None):
        """Ma hoa & ghi file LON theo luong (streaming) - khong nap ca file vao RAM.
        Dinh dang: [MAGIC 'SFST'][16 salt] roi lien tiep cac block [4-byte enc_len][enc].
        Moi block: plaintext CHUNK_PLAIN byte, ma hoa AES-GCM voi nonce = 12-byte counter.
        progress(done_bytes,total_bytes) duoc goi de cap nhat %."""
        s.files=[f for f in s.files if not(f.name==name and f.act)]
        start=s._next_free_sector()
        total_plain=os.path.getsize(src_path)
        sa=os.urandom(16);key=dk(pw,sa);aes=AESGCM(key)
        CHUNK_PLAIN=4*1024*1024  # 4MB moi block
        # Buffer ghi theo boi so sector
        buf=bytearray();buf+=b"SFST"+sa
        cur_sec=start;esz=0;done=0;counter=0
        def flush(final=False):
            nonlocal buf,cur_sec,esz
            # Ghi cac sector day
            n=len(buf)//SECTOR
            if n>0:
                # ghi theo cum <=128 sector
                pos=0
                while pos<n*SECTOR:
                    part=buf[pos:pos+SECTOR*128]
                    disk_write(s.h,s._as(cur_sec),bytes(part))
                    secs=(len(part)+SECTOR-1)//SECTOR
                    cur_sec+=secs;esz+=len(part);pos+=len(part)
                del buf[:n*SECTOR]
            if final and len(buf)>0:
                # sector cuoi con du -> pad va ghi
                pad=bytes(buf)+b'\0'*(SECTOR-len(buf))
                disk_write(s.h,s._as(cur_sec),pad)
                cur_sec+=1;esz+=len(buf);buf=bytearray()
        with open(src_path,"rb")as fi:
            while True:
                chunk=fi.read(CHUNK_PLAIN)
                if not chunk:break
                nonce=counter.to_bytes(12,"big");counter+=1
                enc=aes.encrypt(nonce,chunk,None)
                buf+=struct.pack("<I",len(enc))+enc
                done+=len(chunk)
                if len(buf)>=SECTOR*256:flush(False)
                if progress:progress(done,total_plain)
        flush(True)
        # esz = so byte thuc da ghi (khong tinh padding sector cuoi)
        s.files.append(SectorEntry(name,start,total_plain,esz,True))
        s._write_tbl()
        return True

    def read_file_stream(s,name,dst_path,pw,progress=None):
        """Doc file LON theo luong, giai ma tung block, ghi ra dst_path."""
        ent=None
        for f in s.files:
            if f.name==name and f.act:ent=f;break
        if not ent:return False
        total_sec=(ent.esz+SECTOR-1)//SECTOR
        # Doc header truoc (MAGIC+salt = 20 byte) tu sector dau
        first=disk_read(s.h,s._as(ent.sec),1)
        if first[:4]!=b"SFST":
            # Khong phai file streaming -> fallback doc thuong
            return False
        sa=first[4:20];key=dk(pw,sa);aes=AESGCM(key)
        # Doc toan bo phan con lai theo luong qua 1 con tro sector
        class SecReader:
            def __init__(rs):rs.sec=ent.sec;rs.buf=first[20:];rs.read=SECTOR
            def get(rs,n):
                while len(rs.buf)<n and rs.read<ent.esz:
                    cnt=min(128,total_sec-(rs.read//SECTOR))
                    if cnt<=0:break
                    d=disk_read(s.h,s._as(ent.sec+rs.read//SECTOR),cnt)
                    rs.buf+=d;rs.read+=len(d)
                out=rs.buf[:n];rs.buf=rs.buf[n:];return out
        r=SecReader();counter=0;done=0
        with open(dst_path,"wb")as fo:
            while True:
                lb=r.get(4)
                if len(lb)<4:break
                ln=struct.unpack("<I",lb)[0]
                if ln==0 or ln>16*1024*1024+64:break
                enc=r.get(ln)
                if len(enc)<ln:break
                nonce=counter.to_bytes(12,"big");counter+=1
                try:dec=aes.decrypt(nonce,enc,None)
                except:return False
                fo.write(dec);done+=len(dec)
                if progress:progress(done,ent.sz)
        return True

    def is_stream_file(s,name):
        for f in s.files:
            if f.name==name and f.act:
                try:
                    first=disk_read(s.h,s._as(f.sec),1);return first[:4]==b"SFST"
                except:return False
        return False

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
    def rename_entry(s,old,new):
        """Doi ten entry TAI CHO - khong doc/ghi lai data (chay duoc file lon)."""
        s._read_tbl()
        for f in s.files:
            if f.name==old and f.act:f.name=new;break
        s._write_tbl();return True
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
    def data_bytes(s):
        # Kich thuoc vung du lieu an = phan con lai cua disk sau partition public
        try:
            n=get_disk_length_bytes(s.dn)
            if n>0:return max(0,n-(s.off+DATA_START)*SECTOR)
        except:pass
        return 0
    def get_free(s):
        try:
            db=s.data_bytes()
            if db<=0:return 0
            return max(0,db-s.get_used())
        except:return 0
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

def _free_bytes(path):
    try:return shutil.disk_usage(path).free
    except:return 0

def _fill_to_zero(pub,cb=None):
    """Lap day phan vung 'pub' den khi con 0 byte trong tuyet doi.
    Dung nhieu file va giam dan kich thuoc chunk de khong sot du cluster nao.
    Ket qua: Windows bao 'not enough space' voi MOI file (ke ca vai byte)."""
    idx=0
    # Cac buoc chunk giam dan: 8MB -> 1MB -> 64KB -> 4KB -> 512B -> 1B
    for chunk_sz in (8*1024*1024,1024*1024,64*1024,4096,512,1):
        # Neu da het cho thi thu file moi voi chunk nho hon
        while _free_bytes(pub)>0:
            idx+=1
            fp=os.path.join(pub,"._sysfill"if idx==1 else f"._sysfill{idx}")
            chunk=b'\0'*chunk_sz
            wrote=False
            try:
                with open(fp,"ab")as f:
                    while True:
                        f.write(chunk);f.flush();os.fsync(f.fileno())
                        wrote=True
            except OSError:
                # Het cho voi chunk nay -> chuyen sang chunk nho hon
                pass
            except:pass
            try:
                import ctypes as _c;_c.windll.kernel32.SetFileAttributesW(fp,0x06)
            except:pass
            if cb:
                try:cb(f"Lap day... con trong {_free_bytes(pub)} byte")
                except:pass
            if not wrote:
                # Khong ghi duoc gi voi chunk nay -> thoat vong lap trong
                break
    # Kiem tra lan cuoi: neu van con byte trong, ghi tung byte cho het
    guard=0
    while _free_bytes(pub)>0 and guard<100:
        guard+=1
        fp=os.path.join(pub,f"._sysfill_tail{guard}")
        try:
            with open(fp,"ab")as f:
                while _free_bytes(pub)>0:
                    f.write(b'\0');f.flush()
        except:pass
        try:
            import ctypes as _c;_c.windll.kernel32.SetFileAttributesW(fp,0x06)
        except:pass
    return _free_bytes(pub)

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
    # LAP DAY phan vung EXE -> free = 0 byte tuyet doi -> Windows chan MOI copy ("khong du dung luong")
    # QUAN TRONG: lap den khi 0 byte (giam dan chunk), khong de sot vai KB
    if cb:cb("Khoa phan vung (lap day den 0 byte)...")
    _fill_to_zero(pub,cb)
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

S="""*{font-family:'Segoe UI';font-size:13px;}
QMainWindow,QDialog{background:#ffffff;color:#202020;}
QLabel{color:#202020;font-size:13px;}
QWidget#tb{background:#ffffff;border-bottom:1px solid #e0e0e0;}
QWidget#pnl{background:#ffffff;border:none;}
QToolButton,QPushButton#tbBtn{background:transparent;border:none;padding:6px 12px;color:#202020;font-size:13px;}
QToolButton:hover,QPushButton#tbBtn:hover{background:#eaf1fb;border-radius:4px;}
QPushButton{background:#f0f0f0;border:1px solid #c0c0c0;border-radius:4px;padding:5px 12px;color:#202020;font-size:13px;}
QPushButton:hover{background:#e5eefb;border-color:#7aa7e0;}
QPushButton#bp{background:#1565c0;border:none;color:white;font-weight:bold;}
QPushButton#bp:hover{background:#1976d2;}
QPushButton#arrow{background:transparent;border:none;}
QTreeWidget{background:white;border:1px solid #d0d0d0;outline:none;font-size:13px;}
QTreeWidget::item{padding:4px 2px;border-bottom:1px solid #f0f0f0;}
QTreeWidget::item:selected{background:#cfe3ff;color:#202020;}
QTreeWidget::item:hover{background:#eaf4ff;}
QHeaderView::section{background:#ffffff;color:#404040;border:none;border-bottom:1px solid #d0d0d0;padding:6px 4px;font-size:13px;font-weight:bold;}
QComboBox{background:white;border:1px solid #c0c0c0;border-radius:3px;padding:4px 8px;font-size:13px;}
QComboBox QAbstractItemView{background:white;border:1px solid #c0c0c0;selection-background-color:#cfe3ff;}
QProgressBar{background:#f0f0f0;border:1px solid #d0d0d0;border-radius:2px;height:16px;text-align:center;font-size:11px;}
QProgressBar::chunk{background:#1565c0;}
QLineEdit{background:white;border:1px solid #c0c0c0;border-radius:3px;padding:5px 8px;font-size:13px;color:#202020;}
QLineEdit:focus{border-color:#1565c0;}
QCheckBox{color:#505050;font-size:12px;}
QStatusBar{background:#ffffff;color:#404040;border-top:1px solid #e0e0e0;font-size:12px;}"""

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
        s.setWindowTitle(APP);s.resize(1100,620);s.setMinimumSize(900,500);s.setStyleSheet(S)
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
        s.setWindowTitle(APP)
        st=s.style()
        cw=QWidget();s.setCentralWidget(cw);rt=QVBoxLayout(cw);rt.setContentsMargins(0,0,0,0);rt.setSpacing(0)
        # ===== THANH CONG CU TREN (giong H04) =====
        tb=QWidget();tb.setObjectName("tb");tb.setFixedHeight(52)
        tl=QHBoxLayout(tb);tl.setContentsMargins(10,4,10,4);tl.setSpacing(4)
        def tbtn(text,icon,fn):
            b=QToolButton();b.setText(" "+text);b.setIcon(st.standardIcon(icon))
            b.setToolButtonStyle(Qt.ToolButtonTextBesideIcon);b.setIconSize(QSize(22,22))
            b.clicked.connect(fn);return b
        tl.addWidget(tbtn("Tạo thư mục",QStyle.SP_FileDialogNewFolder,s.mk_usb_folder))
        tl.addWidget(tbtn("Đổi tên",QStyle.SP_FileDialogDetailedView,s.rename_item))
        tl.addWidget(tbtn("Xóa dữ liệu",QStyle.SP_TrashIcon,s.ud))
        tl.addStretch()
        tl.addWidget(tbtn("Đổi mật khẩu",QStyle.SP_DialogYesButton,s.pw_menu))
        tl.addWidget(tbtn("Format USB",QStyle.SP_BrowserReload,s.format_usb))
        hb=QToolButton();hb.setText("?");hb.setFixedSize(30,30);hb.clicked.connect(s.show_help);tl.addWidget(hb)
        rt.addWidget(tb)
        # ===== THAN: 2 KHUNG + MUI TEN GIUA =====
        bd=QWidget();bl_=QHBoxLayout(bd);bl_.setContentsMargins(8,6,8,6);bl_.setSpacing(4)

        # ---- KHUNG TRAI: MAY TINH ----
        pc=QWidget();pc.setObjectName("pnl");pl=QVBoxLayout(pc);pl.setContentsMargins(2,2,2,2);pl.setSpacing(4)
        r1=QHBoxLayout();r1.setSpacing(6)
        s.cd=QComboBox();s.cd.setFixedHeight(28);s.cd.setMinimumWidth(180)
        for d in s._pc_locations():s.cd.addItem(d[0],d[1])
        s.cd.currentIndexChanged.connect(lambda:s.lpc(s.cd.currentData()));r1.addWidget(s.cd)
        r1.addStretch()
        eye=QLabel();eye.setPixmap(st.standardIcon(QStyle.SP_DialogDiscardButton).pixmap(16,16));r1.addWidget(eye)
        s.pc_space=QLabel("Dung lượng còn lại: --");s.pc_space.setStyleSheet("font-size:14px;color:#202020;");r1.addWidget(s.pc_space)
        pl.addLayout(r1)
        r2=QHBoxLayout();r2.setSpacing(4)
        bu=QToolButton();bu.setIcon(st.standardIcon(QStyle.SP_FileDialogToParent));bu.setIconSize(QSize(20,20));bu.clicked.connect(s.pu);r2.addWidget(bu)
        s.plb=QLineEdit();s.plb.setReadOnly(True);r2.addWidget(s.plb,stretch=2)
        rf1=QToolButton();rf1.setIcon(st.standardIcon(QStyle.SP_BrowserReload));rf1.setIconSize(QSize(18,18));rf1.clicked.connect(lambda:s.lpc(s.cp));r2.addWidget(rf1)
        s.pc_search=QLineEdit();s.pc_search.setPlaceholderText("Tìm kiếm");s.pc_search.textChanged.connect(lambda:s.lpc(s.cp));r2.addWidget(s.pc_search,stretch=1)
        pl.addLayout(r2)
        s.tp=QTreeWidget();s.tp.setHeaderLabels(["Tên","Định dạng","Kích cỡ","Ngày chỉnh sửa"])
        s.tp.setSelectionMode(QAbstractItemView.ExtendedSelection);s.tp.setRootIsDecorated(False)
        s.tp.header().setSectionResizeMode(0,QHeaderView.Stretch)
        s.tp.setColumnWidth(1,90);s.tp.setColumnWidth(2,90);s.tp.setColumnWidth(3,150)
        s.tp.itemDoubleClicked.connect(s.pdbl);pl.addWidget(s.tp)
        s.pc_stat=QLabel("0 thư mục, 0 file");s.pc_stat.setStyleSheet("font-size:13px;color:#404040;padding:2px;");pl.addWidget(s.pc_stat)
        bl_.addWidget(pc,stretch=1)

        # ---- GIUA: 2 MUI TEN XANH (ve tay mau xanh giong H04) ----
        ct=QWidget();ct.setFixedWidth(70);cl=QVBoxLayout(ct);cl.setContentsMargins(2,0,2,0);cl.setSpacing(16)
        cl.addStretch(1)
        b1=QToolButton();b1.setObjectName("arrow");b1.setIcon(s._arrow_icon("right"));b1.setIconSize(QSize(52,44))
        b1.setToolTip("Mã hóa & copy sang USB");b1.clicked.connect(s.c2u);cl.addWidget(b1,alignment=Qt.AlignCenter)
        b2=QToolButton();b2.setObjectName("arrow");b2.setIcon(s._arrow_icon("left"));b2.setIconSize(QSize(52,44))
        b2.setToolTip("Giải mã & copy về PC");b2.clicked.connect(s.cfu);cl.addWidget(b2,alignment=Qt.AlignCenter)
        cl.addStretch(2);bl_.addWidget(ct)

        # ---- KHUNG PHAI: USB AN TOAN ----
        ub=QWidget();ub.setObjectName("pnl");ul=QVBoxLayout(ub);ul.setContentsMargins(2,2,2,2);ul.setSpacing(4)
        r3=QHBoxLayout();r3.setSpacing(6)
        s.ucd=QComboBox();s.ucd.setFixedHeight(28);s.ucd.setMinimumWidth(180);s.ucd.addItem("USB AN TOÀN")
        r3.addWidget(s.ucd);r3.addStretch()
        s.usb_space=QLabel("Dung lượng còn lại: --");s.usb_space.setStyleSheet("font-size:14px;color:#202020;");r3.addWidget(s.usb_space)
        ul.addLayout(r3)
        r4=QHBoxLayout();r4.setSpacing(4)
        buu=QToolButton();buu.setIcon(st.standardIcon(QStyle.SP_FileDialogToParent));buu.setIconSize(QSize(20,20));buu.clicked.connect(s.usb_up);r4.addWidget(buu)
        s.ulb=QLineEdit();s.ulb.setReadOnly(True);r4.addWidget(s.ulb,stretch=2)
        rf2=QToolButton();rf2.setIcon(st.standardIcon(QStyle.SP_BrowserReload));rf2.setIconSize(QSize(18,18));rf2.clicked.connect(s.luc);r4.addWidget(rf2)
        s.usb_search=QLineEdit();s.usb_search.setPlaceholderText("Tìm kiếm");s.usb_search.textChanged.connect(lambda:s.luc());r4.addWidget(s.usb_search,stretch=1)
        ul.addLayout(r4)
        s.tu=QTreeWidget();s.tu.setHeaderLabels(["Tên","Định dạng","Kích cỡ","Ngày chỉnh sửa"])
        s.tu.setSelectionMode(QAbstractItemView.ExtendedSelection);s.tu.setRootIsDecorated(False)
        s.tu.header().setSectionResizeMode(0,QHeaderView.Stretch)
        s.tu.setColumnWidth(1,90);s.tu.setColumnWidth(2,90);s.tu.setColumnWidth(3,150)
        s.tu.itemDoubleClicked.connect(s.udbl);ul.addWidget(s.tu)
        s.usb_stat=QLabel("0 thư mục, 0 file");s.usb_stat.setStyleSheet("font-size:13px;color:#404040;padding:2px;");ul.addWidget(s.usb_stat)
        bl_.addWidget(ub,stretch=1)

        rt.addWidget(bd,stretch=1)
        s.pb=QProgressBar();s.pb.setVisible(False);s.pb.setTextVisible(True);rt.addWidget(s.pb)
        s.copy_lbl=QLabel("");s.copy_lbl.setVisible(False)
        s.copy_lbl.setStyleSheet("font-size:14px;font-weight:bold;color:#1565c0;padding:4px 10px;background:#eaf2fd;")
        rt.addWidget(s.copy_lbl)
        s.statusBar().showMessage("USB AN TOÀN - AES-256 | Dữ liệu ẩn, chặn copy trực tiếp")

    def _pc_locations(s):
        # Danh sach vi tri ben PC: Desktop + cac o dia
        locs=[]
        home=str(Path.home())
        dk=os.path.join(home,"Desktop")
        if os.path.isdir(dk):locs.append(("Desktop",dk))
        locs.append(("Documents",os.path.join(home,"Documents")))
        locs.append(("Downloads",os.path.join(home,"Downloads")))
        for d in gd():locs.append((d,d))
        return locs

    def _arrow_icon(s,direction):
        """Ve mui ten mau xanh giong H04."""
        pm=QPixmap(52,44);pm.fill(Qt.transparent)
        p=QPainter(pm);p.setRenderHint(QPainter.Antialiasing)
        p.setBrush(QColor("#1f6fd6"));p.setPen(Qt.NoPen)
        w,h=52,44
        poly=QPolygon()
        if direction=="right":
            poly=QPolygon([QPoint(4,15),QPoint(30,15),QPoint(30,6),QPoint(48,22),
                           QPoint(30,38),QPoint(30,29),QPoint(4,29)])
        else:
            poly=QPolygon([QPoint(48,15),QPoint(22,15),QPoint(22,6),QPoint(4,22),
                           QPoint(22,38),QPoint(22,29),QPoint(48,29)])
        p.drawPolygon(poly);p.end()
        return QIcon(pm)

    def show_help(s):
        QMessageBox.information(s,"Hướng dẫn",
            "USB AN TOÀN\n\n"
            "• Chọn file bên trái (MÁY TÍNH), bấm mũi tên → để mã hóa & copy sang USB\n"
            "• Chọn file bên phải (USB), bấm mũi tên ← để giải mã & copy về máy\n"
            "• Nhấn đúp file trên USB để mở xem\n"
            "• Tạo thư mục / Đổi tên / Xóa dữ liệu ở thanh trên\n"
            "• Đổi mật khẩu: đổi mật khẩu đăng nhập hoặc mã hóa\n"
            "• Format USB: xóa toàn bộ dữ liệu (cần mật khẩu Admin)\n\n"
            "Dữ liệu được ẩn hoàn toàn, không thể copy trực tiếp vào USB.")

    def pw_menu(s):
        m=QMenu(s)
        m.addAction("Đổi mật khẩu đăng nhập",s.clp)
        m.addAction("Đặt / Đổi mật khẩu mã hóa",s.cep)
        m.exec_(QCursor.pos())

    def _mt(s,fp):
        try:return datetime.fromtimestamp(os.path.getmtime(fp)).strftime("%d/%m/%y %H:%M")
        except:return""
    def _fmt_col(s,n,is_dir):
        if is_dir:return ""
        e=os.path.splitext(n)[1].lstrip(".").lower()
        return e if e else "file"
    def lpc(s,p):
        s.tp.clear();s.cp=p;s.plb.setText(p)
        q=s.pc_search.text().strip().lower()if hasattr(s,"pc_search")else""
        st=s.style()
        # Dong "..." de len thu muc cha
        parent=os.path.dirname(p)
        if parent and parent!=p:
            up=QTreeWidgetItem(["...","","",""]);up.setData(0,Qt.UserRole,parent);up.setData(0,Qt.UserRole+1,True)
            up.setData(0,Qt.UserRole+2,"up");up.setIcon(0,st.standardIcon(QStyle.SP_FileDialogToParent));s.tp.addTopLevelItem(up)
        try:es=os.listdir(p)
        except:es=[]
        ds,fl=[],[]
        for n in es:
            if n.startswith("."):continue
            if q and q not in n.lower():continue
            fp=os.path.join(p,n)
            try:
                if os.path.isdir(fp):ds.append((n,fp))
                else:fl.append((n,fp))
            except:pass
        ds.sort(key=lambda x:x[0].lower());fl.sort(key=lambda x:x[0].lower())
        for n,fp in ds:
            it=QTreeWidgetItem([n,"",""," "+s._mt(fp)]);it.setData(0,Qt.UserRole,fp);it.setData(0,Qt.UserRole+1,True)
            it.setIcon(0,st.standardIcon(QStyle.SP_DirIcon));s.tp.addTopLevelItem(it)
        for n,fp in fl:
            try:sz=os.path.getsize(fp)
            except:sz=0
            it=QTreeWidgetItem([n,s._fmt_col(n,False),fs(sz)," "+s._mt(fp)])
            it.setData(0,Qt.UserRole,fp);it.setData(0,Qt.UserRole+1,False)
            it.setIcon(0,st.standardIcon(QStyle.SP_FileIcon));s.tp.addTopLevelItem(it)
        s.pc_stat.setText(f"{len(ds)} thư mục, {len(fl)} file")
        # Dung luong con lai cua o dia PC
        try:
            drv=os.path.splitdrive(p)[0]+os.sep if os.path.splitdrive(p)[0] else p
            u=shutil.disk_usage(drv);s.pc_space.setText(f"Dung lượng còn lại: {fs(u.free)}")
        except:pass
    def pdbl(s,it,c):
        fp=it.data(0,Qt.UserRole)
        if fp and it.data(0,Qt.UserRole+1):s.lpc(fp)
    def pu(s):
        p=os.path.dirname(s.cp)
        if p and p!=s.cp:s.lpc(p)
    def luc(s):
        """Load danh sach USB theo thu muc ao hien tai (usb_path)."""
        s.tu.clear()
        if not s.sfs:return
        st=s.style()
        q=s.usb_search.text().strip().lower()if hasattr(s,"usb_search")else""
        s.sfs._read_tbl()
        prefix=s.usb_path
        s.ulb.setText(("USB AN TOÀN:/"+prefix)if prefix else"USB AN TOÀN:/")
        # Dong "..." de len thu muc cha
        if prefix:
            up=QTreeWidgetItem(["...","","",""]);up.setData(0,Qt.UserRole,"..");up.setData(0,Qt.UserRole+1,True)
            up.setData(0,Qt.UserRole+2,"up");up.setIcon(0,st.standardIcon(QStyle.SP_FileDialogToParent));s.tu.addTopLevelItem(up)
        all_files=s.sfs.list_files()
        subfolders=set();files_here=[]
        for name,sz in all_files:
            if name.endswith("/.keep"):
                rel_marker=name[:-6]
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
        nf=0;nfl=0
        for fold in sorted(subfolders):
            if q and q not in fold.lower():continue
            it=QTreeWidgetItem([fold,"",""," "]);it.setData(0,Qt.UserRole,fold);it.setData(0,Qt.UserRole+1,True)
            it.setIcon(0,st.standardIcon(QStyle.SP_DirIcon));s.tu.addTopLevelItem(it);nf+=1
        for disp,fullname,sz in sorted(files_here):
            if q and q not in disp.lower():continue
            it=QTreeWidgetItem([disp,s._fmt_col(disp,False),fs(sz)," "])
            it.setData(0,Qt.UserRole,fullname);it.setData(0,Qt.UserRole+1,False)
            it.setIcon(0,st.standardIcon(QStyle.SP_FileIcon));s.tu.addTopLevelItem(it);nfl+=1
        s.usb_stat.setText(f"{nf} thư mục, {nfl} file")
        # Dung luong con lai vung du lieu an
        try:
            free=s.sfs.get_free();s.usb_space.setText(f"Dung lượng còn lại: {fs(free)}")
        except:
            try:
                used=s.sfs.get_used();total=s.sfs.data_bytes();s.usb_space.setText(f"Dung lượng còn lại: {fs(max(0,total-used))}")
            except:pass
        s.us()
    def usb_up(s):
        if s.usb_path:
            s.usb_path="/".join(s.usb_path.split("/")[:-1])
            s.luc()
    def mk_usb_folder(s):
        n,ok=QInputDialog.getText(s,"Tạo thư mục","Tên thư mục mới:")
        if not ok or not n.strip():return
        n=n.strip().replace("/","_").replace("\\","_")
        # Tao thu muc ao bang 1 file danh dau an (.keep)
        marker=(s.usb_path+"/"if s.usb_path else"")+n+"/.keep"
        pw=s._gep()
        if not pw:return
        try:
            s.sfs.write_file(marker,aes_enc(b"",pw))
            s.luc()
        except Exception as e:QMessageBox.critical(s,"",f"Lỗi: {e}")

    def format_usb(s):
        """Xoa toan bo du lieu USB - can mat khau Admin (giong H04)."""
        pw,ok=QInputDialog.getText(s,"Format USB","Nhập mật khẩu Admin để xóa toàn bộ dữ liệu:",QLineEdit.Password)
        if not ok:return
        if pw!=ADMIN:
            QMessageBox.critical(s,"","Sai mật khẩu Admin!");return
        if QMessageBox.warning(s,"Xác nhận Format",
            "XÓA TOÀN BỘ dữ liệu trên USB AN TOÀN?\nKhông thể khôi phục!",
            QMessageBox.Yes|QMessageBox.No)!=QMessageBox.Yes:return
        try:
            s.sfs.rebuild([])   # xoa sach vung du lieu
            s.usb_path=""
            s.luc()
            QMessageBox.information(s,"","Đã format USB AN TOÀN - dữ liệu đã xóa sạch.")
        except Exception as e:
            QMessageBox.critical(s,"",f"Lỗi format: {e}")

    def rename_item(s):
        """Doi ten file/thu muc dang chon ben USB (giong H04)."""
        sel=s.tu.selectedItems()
        if not sel:
            QMessageBox.information(s,"","Chọn 1 file hoặc thư mục bên USB để đổi tên.");return
        it=sel[0]
        old=it.data(0,Qt.UserRole);is_folder=it.data(0,Qt.UserRole+1)
        if old=="..":return
        cur=old.split("/")[-1]if not is_folder else old
        new,ok=QInputDialog.getText(s,"Đổi tên","Tên mới:",text=cur)
        if not ok or not new.strip():return
        new=new.strip().replace("/","_").replace("\\","_")
        try:
            s.sfs._read_tbl()
            prefix=s.usb_path
            if is_folder:
                # Doi ten thu muc: doi prefix cua tat ca file ben trong (tai cho)
                base=(prefix+"/"if prefix else"")+old
                newbase=(prefix+"/"if prefix else"")+new
                changed=[]
                for f in list(s.sfs.files):
                    if f.name==base+"/.keep" or f.name.startswith(base+"/"):
                        rest=f.name[len(base):]
                        changed.append((f.name,newbase+rest))
                for oldn,newn in changed:
                    s.sfs.rename_entry(oldn,newn)
            else:
                # Doi ten file: giu nguyen thu muc, doi phan cuoi (tai cho, chay file lon)
                parent="/".join(old.split("/")[:-1])
                newn=(parent+"/"if parent else"")+new
                s.sfs.rename_entry(old,newn)
            s.luc()
        except Exception as e:
            QMessageBox.critical(s,"",f"Lỗi đổi tên: {e}")
    def udbl(s,it,c):
        name=it.data(0,Qt.UserRole)
        is_folder=it.data(0,Qt.UserRole+1)
        if name=="..":
            s.usb_up();return
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
        tmp=tempfile.mkdtemp(prefix="usbat_")
        out=os.path.join(tmp,os.path.basename(name))
        try:
            if s.sfs.is_stream_file(name):
                # File lon - giai ma theo luong ra file tam
                s.copy_lbl.setVisible(True);s.pb.setVisible(True)
                def prog(dn,tt):
                    pct=int(dn/max(1,tt)*100);s.pb.setValue(pct)
                    s.copy_lbl.setText(f"Đang mở (giải mã): {fs(dn)} / {fs(tt)} ({pct}%)");QApplication.processEvents()
                okk=s.sfs.read_file_stream(name,out,pw,progress=prog)
                s.pb.setVisible(False);s.copy_lbl.setVisible(False)
                if not okk:QMessageBox.critical(s,"","Sai mật khẩu hoặc file lỗi!");return
            else:
                data=s.sfs.read_file(name)
                if not data:QMessageBox.critical(s,"","Không đọc được!");return
                dec=aes_dec(data,pw);del data
                with open(out,"wb")as f:f.write(dec)
            s._t.append(tmp)
            if sys.platform=="win32":os.startfile(out)
            else:subprocess.Popen(["xdg-open",out])
        except:QMessageBox.critical(s,"","Sai mật khẩu!")
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
        items=[]
        for it in sl:
            fp=it.data(0,Qt.UserRole)
            if not fp:continue
            if it.data(0,Qt.UserRole+1):
                folder_base=os.path.dirname(fp)
                for root,_,files in os.walk(fp):
                    for fn in files:
                        full=os.path.join(root,fn)
                        rel=os.path.relpath(full,folder_base).replace("\\","/")
                        items.append((full,prefix+rel))
                if not any(True for _,_,fs_ in os.walk(fp) for _ in fs_):
                    items.append((None,prefix+os.path.basename(fp)+"/.keep"))
            else:
                items.append((fp,prefix+os.path.basename(fp)))
        if not items:QMessageBox.information(s,"","Không có gì để copy!");return
        # Tong dung luong de tinh % chung
        total_bytes=0
        for full,_ in items:
            if full:
                try:total_bytes+=os.path.getsize(full)
                except:pass
        total_bytes=max(1,total_bytes)
        s.pb.setVisible(True);s.pb.setValue(0)
        s.copy_lbl.setVisible(True)
        ok_count=0;done_total=[0]
        import time as _t;t0=_t.time()
        for i,(full,name) in enumerate(items):
            try:
                if full is None:
                    s.sfs.write_file(name,aes_enc(b"",pw))
                else:
                    sz=os.path.getsize(full)
                    base_done=done_total[0]
                    def prog(d,t,_i=i,_n=name,_sz=sz,_base=base_done):
                        cur=_base+d
                        pct=int(cur/total_bytes*100)
                        s.pb.setValue(pct)
                        el=max(0.001,_t.time()-t0);spd=cur/el
                        s.pb.setFormat(f"[{_i+1}/{len(items)}] {os.path.basename(_n)} - {pct}%")
                        s.copy_lbl.setText(
                            f"Đang copy: {fs(cur)} / {fs(total_bytes)}  ({pct}%)   |   "
                            f"Tốc độ: {fs(spd)}/s")
                        QApplication.processEvents()
                    # STREAMING - khong nap ca file vao RAM -> chay duoc file 16GB+
                    s.sfs.write_file_stream(name,full,pw,progress=prog)
                    done_total[0]+=sz
                ok_count+=1
            except MemoryError:
                QMessageBox.critical(s,"",f"File quá lớn, thiếu RAM: {name}")
            except Exception as e:QMessageBox.critical(s,"",f"Lỗi {name}: {e}")
        s.pb.setValue(100);s.pb.setFormat("Hoàn tất 100%")
        s.copy_lbl.setText(f"Đã copy xong {fs(done_total[0])} ({ok_count}/{len(items)} file)")
        QTimer.singleShot(4000,lambda:(s.pb.setVisible(False),s.copy_lbl.setVisible(False)))
        s.luc();QMessageBox.information(s,"",f"Đã mã hóa {ok_count}/{len(items)} file vào USB!")
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
        if not names:QMessageBox.information(s,"","Không có file!");return
        # Tong dung luong (theo sz goc luu trong entry) de tinh %
        total_bytes=0;name_sz={}
        for f in s.sfs.files:
            if f.name in names:name_sz[f.name]=f.sz;total_bytes+=f.sz
        total_bytes=max(1,total_bytes)
        s.pb.setVisible(True);s.pb.setValue(0);s.copy_lbl.setVisible(True)
        ok_count=0;done_total=[0]
        import time as _t;t0=_t.time()
        for i,name in enumerate(names):
            rel=name
            out=os.path.join(s.cp,rel.replace("/",os.sep))
            d=os.path.dirname(out)
            if d:os.makedirs(d,exist_ok=True)
            b,e=os.path.splitext(out);c=1
            while os.path.exists(out):out=f"{b}({c}){e}";c+=1
            base_done=done_total[0]
            try:
                if s.sfs.is_stream_file(name):
                    # File LON - giai ma theo luong
                    def prog(dn,tt,_i=i,_n=name,_base=base_done):
                        cur=_base+dn;pct=int(cur/total_bytes*100)
                        s.pb.setValue(pct)
                        el=max(0.001,_t.time()-t0);spd=cur/el
                        s.pb.setFormat(f"[{_i+1}/{len(names)}] {os.path.basename(_n)} - {pct}%")
                        s.copy_lbl.setText(f"Đang giải mã: {fs(cur)} / {fs(total_bytes)}  ({pct}%)   |   Tốc độ: {fs(spd)}/s")
                        QApplication.processEvents()
                    okk=s.sfs.read_file_stream(name,out,pw,progress=prog)
                    if not okk:
                        QMessageBox.critical(s,"","Sai mật khẩu hoặc file lỗi!");s.pb.setVisible(False);s.copy_lbl.setVisible(False);return
                else:
                    # File nho - doc thuong
                    data=s.sfs.read_file(name)
                    if not data:continue
                    dec=aes_dec(data,pw);del data
                    with open(out,"wb")as f:f.write(dec)
                    del dec
                done_total[0]+=name_sz.get(name,0)
                s.pb.setValue(int(done_total[0]/total_bytes*100))
                s.copy_lbl.setText(f"Đã giải mã: {fs(done_total[0])} / {fs(total_bytes)}")
                QApplication.processEvents();ok_count+=1
            except Exception:
                QMessageBox.critical(s,"","Sai mật khẩu!");s.pb.setVisible(False);s.copy_lbl.setVisible(False);return
        s.pb.setValue(100);s.pb.setFormat("Hoàn tất 100%")
        s.copy_lbl.setText(f"Đã giải mã xong {fs(done_total[0])} ({ok_count} file)")
        QTimer.singleShot(4000,lambda:(s.pb.setVisible(False),s.copy_lbl.setVisible(False)))
        s.lpc(s.cp);QMessageBox.information(s,"",f"Đã giải mã {ok_count} mục về máy!")
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
        s.pb.setVisible(True);s.copy_lbl.setVisible(True)
        files=list(s.sfs.list_files())
        tmpdir=tempfile.mkdtemp(prefix="usbat_cep_")
        try:
            # 1) Giai ma tat ca ra file tam (theo luong voi file lon)
            plain=[]  # (name, tmp_path_or_bytes, is_bytes)
            for i,(name,_) in enumerate(files):
                s.pb.setValue(int(i/max(len(files),1)*50));QApplication.processEvents()
                s.copy_lbl.setText(f"Đang giải mã lại: {name}")
                if name.endswith("/.keep"):
                    plain.append((name,b"",True));continue
                if s.sfs.is_stream_file(name):
                    tp=os.path.join(tmpdir,f"f{i}.tmp")
                    if not s.sfs.read_file_stream(name,tp,old):
                        QMessageBox.critical(s,"","Sai MK cũ!");s.pb.setVisible(False);s.copy_lbl.setVisible(False);shutil.rmtree(tmpdir,True);return
                    plain.append((name,tp,False))
                else:
                    data=s.sfs.read_file(name)
                    try:dec=aes_dec(data,old)if data else b""
                    except:
                        QMessageBox.critical(s,"","Sai MK cũ!");s.pb.setVisible(False);s.copy_lbl.setVisible(False);shutil.rmtree(tmpdir,True);return
                    plain.append((name,dec,True))
            # 2) Xoa het + ghi lai voi MK moi
            s.sfs.rebuild([])  # xoa sach
            for i,(name,payload,is_bytes) in enumerate(plain):
                s.pb.setValue(50+int(i/max(len(plain),1)*50));QApplication.processEvents()
                s.copy_lbl.setText(f"Đang mã hóa lại: {name}")
                if is_bytes:
                    s.sfs.write_file(name,aes_enc(payload,npw))
                else:
                    s.sfs.write_file_stream(name,payload,npw)
        finally:
            shutil.rmtree(tmpdir,True)
        s.pb.setValue(100);QTimer.singleShot(1500,lambda:(s.pb.setVisible(False),s.copy_lbl.setVisible(False)))
        sa=os.urandom(16);s.cfg["enc_salt"]=sa.hex();s.cfg["enc_hash"]=hp(npw,sa).hex()
        s.sfs.write_config(s.cfg);s.ep=npw
        s.luc();QMessageBox.information(s,"",f"Đổi MK mã hóa thành công!\nĐã mã hóa lại {len(files)} file.")
    def clp(s):
        d1=PwD("","MK cu",s.cfg,"login",s)
        if d1.exec_()!=QDialog.Accepted:return
        pw,ok=QInputDialog.getText(s,"","MK moi (>=6):",QLineEdit.Password)
        if not ok or len(pw)<6:return
        sa=os.urandom(16);s.cfg["salt"]=sa.hex();s.cfg["pw_hash"]=hp(pw,sa).hex();s.cfg["att"]=5;s.sfs.write_config(s.cfg)
        QMessageBox.information(s,"","Doi MK thanh cong!")
    def us(s):
        if s.sfs:
            try:s.statusBar().showMessage(f"USB AN TOÀN - AES-256 | Đã dùng: {fs(s.sfs.get_used())} | Dữ liệu ẩn, chặn copy trực tiếp")
            except:pass
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
