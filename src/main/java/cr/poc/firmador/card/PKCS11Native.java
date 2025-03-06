package cr.poc.firmador.card;

import com.sun.jna.*;
import com.sun.jna.ptr.LongByReference;
import cr.poc.firmador.sign.CRSigner;

public interface PKCS11Native extends Library {
    PKCS11Native INSTANCE = Native.load(CRSigner.getPkcs11Lib(), PKCS11Native.class);

    long CKF_SERIAL_SESSION = 4;
    long CKF_RW_SESSION = 2;
    
    // Object classes
    long CKO_CERTIFICATE = 1;
    long CKC_X_509 = 0;
    
    // Certificate categories
    long CKA_CLASS = 0;
    long CKA_CERTIFICATE_TYPE = 0x80;
    long CKA_VALUE = 0x11;
    
    long C_Initialize(Pointer initArgs);
    long C_Finalize(Pointer reserved);
    long C_GetSlotList(boolean tokenPresent, long[] slotList, LongByReference count);
    long C_GetTokenInfo(long slotID, TokenInfo tokenInfo);
    long C_OpenSession(long slotID, long flags, Pointer application, Pointer notify, LongByReference session);
    long C_CloseSession(long session);
    long C_FindObjectsInit(long session, CKAttribute[] template, long count);
    long C_FindObjects(long session, long[] objects, long maxObjects, LongByReference count);
    long C_FindObjectsFinal(long session);
    long C_GetAttributeValue(long session, long object, CKAttribute[] template, long count);
    
    @Structure.FieldOrder({"type", "pValue", "ulValueLen"})
    class CKAttribute extends Structure {
        public long type;
        public Pointer pValue;
        public long ulValueLen;
        
        public CKAttribute() {
            super();
        }
        
        public CKAttribute(long type, long value) {
            super();
            this.type = type;
            this.ulValueLen = NativeLong.SIZE;
            this.pValue = new Memory(NativeLong.SIZE);
            this.pValue.setLong(0, value);
            allocateMemory();
        }
        
        public CKAttribute(long type) {
            super();
            this.type = type;
            this.pValue = null;
            this.ulValueLen = 0;
            allocateMemory();
        }

        public static CKAttribute[] createTemplate(CKAttribute... attrs) {
            CKAttribute[] template = (CKAttribute[]) new CKAttribute().toArray(attrs.length);
            for (int i = 0; i < attrs.length; i++) {
                template[i].type = attrs[i].type;
                template[i].pValue = attrs[i].pValue;
                template[i].ulValueLen = attrs[i].ulValueLen;
                template[i].write();
            }
            return template;
        }
    }

    @Structure.FieldOrder({"label", "manufacturerID", "model", "serialNumber", "flags", "ulMaxSessionCount",
            "ulSessionCount", "ulMaxRwSessionCount", "ulRwSessionCount", "ulMaxPinLen", "ulMinPinLen",
            "ulTotalPublicMemory", "ulFreePublicMemory", "ulTotalPrivateMemory", "ulFreePrivateMemory",
            "hardwareVersion", "firmwareVersion", "utcTime"})
    class TokenInfo extends Structure {
        public byte[] label = new byte[32];
        public byte[] manufacturerID = new byte[32];
        public byte[] model = new byte[16];
        public byte[] serialNumber = new byte[16];
        public long flags;
        public long ulMaxSessionCount;
        public long ulSessionCount;
        public long ulMaxRwSessionCount;
        public long ulRwSessionCount;
        public long ulMaxPinLen;
        public long ulMinPinLen;
        public long ulTotalPublicMemory;
        public long ulFreePublicMemory;
        public long ulTotalPrivateMemory;
        public long ulFreePrivateMemory;
        public Version hardwareVersion;
        public Version firmwareVersion;
        public byte[] utcTime = new byte[16];
    }

    @Structure.FieldOrder({"major", "minor"})
    class Version extends Structure {
        public byte major;
        public byte minor;
    }
}