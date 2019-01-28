package com.jiangwei.encodefunc;

import com.jiangwei.encodefunc.ElfType32.Elf32_Sym;
import com.jiangwei.encodefunc.ElfType32.elf32_dyn;
import com.jiangwei.encodefunc.ElfType32.elf32_phdr;
import com.jiangwei.encodefunc.ElfType32.elf32_shdr;

public class EncodeFunc {

    private static String[] funcNameList = {"Java_com_tal_xes_app_common_utils_JNIUtil_getKey"
            , "Java_com_tal_xes_app_common_utils_JNIUtil_getRsaKey"
            , "Java_com_tal_xes_app_common_utils_JNIUtil_hmac"};

    private static ElfType32 type_32 = new ElfType32();

    public static void main(String[] args) {

        byte[] fileByteArys = Utils.readFile("so/libxessafe.so");
        if (fileByteArys == null) {
            System.out.println("read file byte failed...");
            return;
        }

        /**
         * 解析so文件
         * 寻找目标方法并加密
         *
         */
        parseSo(fileByteArys);

        for (int i = 0; i < funcNameList.length; i++) {
            encodeFunc(fileByteArys, funcNameList[i]);
            System.out.println("funcName" + i + ": " + funcNameList[i]);
        }

        parseSo(fileByteArys);

        Utils.saveFile("so/libxessafes.so", fileByteArys);

    }

    private static void encodeFunc(byte[] fileByteArys, String funcName) {
        //寻找Dynamic段的偏移值和大小
        int dy_offset = 0, dy_size = 0;
        for (elf32_phdr phdr : type_32.phdrList) {
            if (Utils.byte2Int(phdr.p_type) == ElfType32.PT_DYNAMIC) {
                dy_offset = Utils.byte2Int(phdr.p_offset);
                dy_size = Utils.byte2Int(phdr.p_filesz);
            }
        }
        System.out.println("dy_size:" + dy_size);
        int dynSize = 8;
        int size = dy_size / dynSize;
        System.out.println("size:" + size);
        byte[] dest = new byte[dynSize];
        for (int i = 0; i < size; i++) {
            System.arraycopy(fileByteArys, i * dynSize + dy_offset, dest, 0, dynSize);
            type_32.dynList.add(parseDynamic(dest));
        }

        //type_32.printDynList();

        byte[] symbolStr = null;
        int strSize = 0, strOffset = 0;
        int symbolOffset = 0;
        int dynHashOffset = 0;
        int funcIndex = 0;
        int symbolSize = 16;

        for (elf32_dyn dyn : type_32.dynList) {
            if (Utils.byte2Int(dyn.d_tag) == ElfType32.DT_HASH) {
                dynHashOffset = Utils.byte2Int(dyn.d_ptr);
            } else if (Utils.byte2Int(dyn.d_tag) == ElfType32.DT_STRTAB) {
                System.out.println("strtab:" + dyn);
                strOffset = Utils.byte2Int(dyn.d_ptr);
            } else if (Utils.byte2Int(dyn.d_tag) == ElfType32.DT_SYMTAB) {
                System.out.println("systab:" + dyn);
                symbolOffset = Utils.byte2Int(dyn.d_ptr);
            } else if (Utils.byte2Int(dyn.d_tag) == ElfType32.DT_STRSZ) {
                System.out.println("strsz:" + dyn);
                strSize = Utils.byte2Int(dyn.d_val);
            }
        }

        symbolStr = Utils.copyBytes(fileByteArys, strOffset, strSize);
        //打印所有的Symbol Name,注意用0来进行分割，C中的字符串都是用0做结尾的
        /*String[] strAry = new String(symbolStr).split(new String(new byte[]{0}));
        for(String str : strAry){
			System.out.println(str);
		}*/

        for (elf32_dyn dyn : type_32.dynList) {
            if (Utils.byte2Int(dyn.d_tag) == ElfType32.DT_HASH) {
                //这里的逻辑有点绕
                /**
                 * 根据hash值，找到下标hash % nbuckets的bucket；根据bucket中的值，读取.dynsym中的对应索引的Elf32_Sym符号；
                 * 从符号的st_name所以找到在.dynstr中对应的字符串与函数名进行比较。若不等，则根据chain[hash % nbuckets]找下一个Elf32_Sym符号，
                 * 直到找到或者chain终止为止。这里叙述得有些复杂，直接上代码。
                 for(i = bucket[funHash % nbucket]; i != 0; i = chain[i]){
                 if(strcmp(dynstr + (funSym + i)->st_name, funcName) == 0){
                 flag = 0;
                 break;
                 }
                 }
                 */
                int nbucket = Utils.byte2Int(Utils.copyBytes(fileByteArys, dynHashOffset, 4));
                int nchian = Utils.byte2Int(Utils.copyBytes(fileByteArys, dynHashOffset + 4, 4));
                int hash = (int) elfhash(funcName.getBytes());
                hash = (hash % nbucket);
                //这里的8是读取nbucket和nchian的两个值
                funcIndex = Utils.byte2Int(Utils.copyBytes(fileByteArys, dynHashOffset + hash * 4 + 8, 4));
                System.out.println("nbucket:" + nbucket + ",hash:" + hash + ",funcIndex:" + funcIndex + ",chian:" + nchian);
                System.out.println("sym:" + Utils.bytes2HexString(Utils.int2Byte(symbolOffset)));
                System.out.println("hash:" + Utils.bytes2HexString(Utils.int2Byte(dynHashOffset)));

                byte[] des = new byte[symbolSize];
                System.arraycopy(fileByteArys, symbolOffset + funcIndex * symbolSize, des, 0, symbolSize);
                Elf32_Sym sym = parseSymbolTable(des);
                System.out.println("sym:" + sym);
                boolean isFindFunc = Utils.isEqualByteAry(symbolStr, Utils.byte2Int(sym.st_name), funcName);
                if (isFindFunc) {
                    System.out.println("find func....");
                    return;
                }

                while (true) {
                    /**
                     *  lseek(fd, dyn_hash + 4 * (2 + nbucket + funIndex), SEEK_SET);
                     if(read(fd, &funIndex, 4) != 4){
                     puts("Read funIndex failed\n");
                     goto _error;
                     }
                     */
                    //System.out.println("dyHash:"+Utils.bytes2HexString(Utils.int2Byte(dynHashOffset))+",nbucket:"+nbucket+",funIndex:"+funcIndex);
                    funcIndex = Utils.byte2Int(Utils.copyBytes(fileByteArys, dynHashOffset + 4 * (2 + nbucket + funcIndex), 4));
                    System.out.println("funcIndex:" + funcIndex);

                    System.arraycopy(fileByteArys, symbolOffset + funcIndex * symbolSize, des, 0, symbolSize);
                    sym = parseSymbolTable(des);

                    isFindFunc = Utils.isEqualByteAry(symbolStr, Utils.byte2Int(sym.st_name), funcName);
                    if (isFindFunc) {
                        System.out.println("find func...");
                        int funcSize = Utils.byte2Int(sym.st_size);
                        int funcOffset = Utils.byte2Int(sym.st_value);
                        System.out.println("size:" + funcSize + ",funcOffset:" + funcOffset);
                        //进行目标函数代码部分进行加密
                        //这里需要注意的是从funcOffset-1的位置开始
                        byte[] funcAry = Utils.copyBytes(fileByteArys, funcOffset - 1, funcSize);
                        for (int i = 0; i < funcAry.length - 1; i++) {
                            funcAry[i] = (byte) (funcAry[i] ^ 0xFF);
                        }
                        Utils.replaceByteAry(fileByteArys, funcOffset - 1, funcAry);
                        break;
                    }
                }
                break;
            }

        }

    }

    private static elf32_dyn parseDynamic(byte[] src) {
        elf32_dyn dyn = new elf32_dyn();
        dyn.d_tag = Utils.copyBytes(src, 0, 4);
        dyn.d_ptr = Utils.copyBytes(src, 4, 4);
        dyn.d_val = Utils.copyBytes(src, 4, 4);
        return dyn;
    }

    private static void parseSo(byte[] fileByteArys) {
        //解析Elf的头部信息
        //System.out.println("+++++++++++++++++++Elf Header+++++++++++++++++");
        parseHeader(fileByteArys, 0);
        System.out.println("header:\n" + type_32.hdr.toString());

        //解析程序头信息
        //System.out.println();
        //System.out.println("+++++++++++++++++++Program Header+++++++++++++++++");
        int p_header_offset = Utils.byte2Int(type_32.hdr.e_phoff);
        parseProgramHeaderList(fileByteArys, p_header_offset);
        type_32.printPhdrList();

        //解析段头信息
        //System.out.println();
        //System.out.println("+++++++++++++++++++Section Header++++++++++++++++++");
        int s_header_offset = Utils.byte2Int(type_32.hdr.e_shoff);
        parseSectionHeaderList(fileByteArys, s_header_offset);
//        type_32.printShdrList();

        //
        /*byte[] names = Utils.copyBytes(fileByteArys, offset, size);
        String str = new String(names);
		byte NULL = 0;//�ַ����Ľ�����
		StringTokenizer st = new StringTokenizer(str, new String(new byte[]{NULL}));
		System.out.println( "Token Total: " + st.countTokens() );
		while(st.hasMoreElements()){
			System.out.println(st.nextToken());
		}
		System.out.println("");*/

        //��ȡ���ű���Ϣ(Symbol Table)
        /*System.out.println();
        System.out.println("+++++++++++++++++++Symbol Table++++++++++++++++++");
		//������Ҫע����ǣ���Elf����û���ҵ�SymbolTable����Ŀ������������ϸ�۲�Section�е�Type=DYNSYM�ε���Ϣ���Եõ�������εĴ�С��ƫ�Ƶ�ַ����SymbolTable�Ľṹ��С�ǹ̶���16���ֽ�
		//��ô�������Ŀ=��С/�ṹ��С
		//������SectionHeader�в��ҵ�dynsym�ε���Ϣ
		int offset_sym = 0;
		int total_sym = 0;
		for(elf32_shdr shdr : type_32.shdrList){
			if(Utils.byte2Int(shdr.sh_type) == ElfType32.SHT_DYNSYM){
				total_sym = Utils.byte2Int(shdr.sh_size);
				offset_sym = Utils.byte2Int(shdr.sh_offset);
				break;
			}
		}
		int num_sym = total_sym / 16;
		System.out.println("sym num="+num_sym);
		parseSymbolTableList(fileByteArys, num_sym, offset_sym);
		type_32.printSymList();*/

		/*//��ȡ�ַ�������Ϣ(String Table)
        System.out.println();
		System.out.println("+++++++++++++++++++Symbol Table++++++++++++++++++");
		//������Ҫע����ǣ���Elf����û���ҵ�StringTable����Ŀ������������ϸ�۲�Section�е�Type=STRTAB�ε���Ϣ�����Եõ�������εĴ�С��ƫ�Ƶ�ַ������������ʱ�����ǲ�֪���ַ����Ĵ�С�����Ծͻ�ȡ������Ŀ��
		//�������ǿ��Բ鿴Section�ṹ�е�name�ֶΣ���ʾƫ��ֵ����ô���ǿ���ͨ�����ֵ����ȡ�ַ����Ĵ�С
		//������ô��⣺��ǰ�ε�nameֵ ��ȥ ��һ�ε�name��ֵ = (��һ�ε�name�ַ����ĳ���)
		//���Ȼ�ȡÿ���ε�name���ַ�����С
		int prename_len = 0;
		int[] lens = new int[type_32.shdrList.size()];
		int total = 0;
		for(int i=0;i<type_32.shdrList.size();i++){
			if(Utils.byte2Int(type_32.shdrList.get(i).sh_type) == ElfType32.SHT_STRTAB){
				int curname_offset = Utils.byte2Int(type_32.shdrList.get(i).sh_name);
				lens[i] = curname_offset - prename_len - 1;
				if(lens[i] < 0){
					lens[i] = 0;
				}
				total += lens[i];
				System.out.println("total:"+total);
				prename_len = curname_offset;
				//������Ҫע����ǣ����һ���ַ����ĳ��ȣ���Ҫ���ܳ��ȼ�ȥǰ��ĳ����ܺ�����ȡ��
				if(i == (lens.length - 1)){
					System.out.println("size:"+Utils.byte2Int(type_32.shdrList.get(i).sh_size));
					lens[i] = Utils.byte2Int(type_32.shdrList.get(i).sh_size) - total - 1;
				}
			}
		}
		for(int i=0;i<lens.length;i++){
			System.out.println("len:"+lens[i]);
		}
		//������Ǹ��������ã����Ƿ���StringTable�е�ÿ���ַ�������������һ��00(��˵�е��ַ���������)����ô����ֻҪ֪��StringTable�Ŀ�ʼλ�ã�Ȼ��Ϳ��Զ�ȡ��ÿ���ַ�����ֵ��
       */
    }

    /**
     * 解析elf的头部信息
     *
     * @param header
     */
    private static void parseHeader(byte[] header, int offset) {
        if (header == null) {
            System.out.println("header is null");
            return;
        }
        /**
         *  public byte[] e_ident = new byte[16];
         public short e_type;
         public short e_machine;
         public int e_version;
         public int e_entry;
         public int e_phoff;
         public int e_shoff;
         public int e_flags;
         public short e_ehsize;
         public short e_phentsize;
         public short e_phnum;
         public short e_shentsize;
         public short e_shnum;
         public short e_shstrndx;
         */
        type_32.hdr.e_ident = Utils.copyBytes(header, 0, 16);//ħ��
        type_32.hdr.e_type = Utils.copyBytes(header, 16, 2);
        type_32.hdr.e_machine = Utils.copyBytes(header, 18, 2);
        type_32.hdr.e_version = Utils.copyBytes(header, 20, 4);
        type_32.hdr.e_entry = Utils.copyBytes(header, 24, 4);
        type_32.hdr.e_phoff = Utils.copyBytes(header, 28, 4);
        type_32.hdr.e_shoff = Utils.copyBytes(header, 32, 4);
        type_32.hdr.e_flags = Utils.copyBytes(header, 36, 4);
        type_32.hdr.e_ehsize = Utils.copyBytes(header, 40, 2);
        type_32.hdr.e_phentsize = Utils.copyBytes(header, 42, 2);
        type_32.hdr.e_phnum = Utils.copyBytes(header, 44, 2);
        type_32.hdr.e_shentsize = Utils.copyBytes(header, 46, 2);
        type_32.hdr.e_shnum = Utils.copyBytes(header, 48, 2);
        type_32.hdr.e_shstrndx = Utils.copyBytes(header, 50, 2);
    }

    /**
     * 解析程序头信息
     *
     * @param header
     */
    public static void parseProgramHeaderList(byte[] header, int offset) {
        int header_size = 32;//32字节
        int header_count = Utils.byte2Short(type_32.hdr.e_phnum);//头部的个数
        byte[] des = new byte[header_size];
        for (int i = 0; i < header_count; i++) {
            System.arraycopy(header, i * header_size + offset, des, 0, header_size);
            type_32.phdrList.add(parseProgramHeader(des));
        }
    }

    private static elf32_phdr parseProgramHeader(byte[] header) {
        /**
         *  public int p_type;
         public int p_offset;
         public int p_vaddr;
         public int p_paddr;
         public int p_filesz;
         public int p_memsz;
         public int p_flags;
         public int p_align;
         */
        ElfType32.elf32_phdr phdr = new ElfType32.elf32_phdr();
        phdr.p_type = Utils.copyBytes(header, 0, 4);
        phdr.p_offset = Utils.copyBytes(header, 4, 4);
        phdr.p_vaddr = Utils.copyBytes(header, 8, 4);
        phdr.p_paddr = Utils.copyBytes(header, 12, 4);
        phdr.p_filesz = Utils.copyBytes(header, 16, 4);
        phdr.p_memsz = Utils.copyBytes(header, 20, 4);
        phdr.p_flags = Utils.copyBytes(header, 24, 4);
        phdr.p_align = Utils.copyBytes(header, 28, 4);
        return phdr;

    }

    /**
     * //解析段头信息
     */
    public static void parseSectionHeaderList(byte[] header, int offset) {
        int header_size = 40;//40个字节
        int header_count = Utils.byte2Short(type_32.hdr.e_shnum);//头部的个数
        byte[] des = new byte[header_size];
        for (int i = 0; i < header_count; i++) {
            System.arraycopy(header, i * header_size + offset, des, 0, header_size);
            type_32.shdrList.add(parseSectionHeader(des));
        }
    }

    private static elf32_shdr parseSectionHeader(byte[] header) {
        ElfType32.elf32_shdr shdr = new ElfType32.elf32_shdr();
        /**
         *  public byte[] sh_name = new byte[4];
         public byte[] sh_type = new byte[4];
         public byte[] sh_flags = new byte[4];
         public byte[] sh_addr = new byte[4];
         public byte[] sh_offset = new byte[4];
         public byte[] sh_size = new byte[4];
         public byte[] sh_link = new byte[4];
         public byte[] sh_info = new byte[4];
         public byte[] sh_addralign = new byte[4];
         public byte[] sh_entsize = new byte[4];
         */
        shdr.sh_name = Utils.copyBytes(header, 0, 4);
        shdr.sh_type = Utils.copyBytes(header, 4, 4);
        shdr.sh_flags = Utils.copyBytes(header, 8, 4);
        shdr.sh_addr = Utils.copyBytes(header, 12, 4);
        shdr.sh_offset = Utils.copyBytes(header, 16, 4);
        shdr.sh_size = Utils.copyBytes(header, 20, 4);
        shdr.sh_link = Utils.copyBytes(header, 24, 4);
        shdr.sh_info = Utils.copyBytes(header, 28, 4);
        shdr.sh_addralign = Utils.copyBytes(header, 32, 4);
        shdr.sh_entsize = Utils.copyBytes(header, 36, 4);
        return shdr;
    }

    /**
     * ����Symbol Table����
     */
    public static void parseSymbolTableList(byte[] header, int header_count, int offset) {
        int header_size = 16;//16���ֽ�
        byte[] des = new byte[header_size];
        for (int i = 0; i < header_count; i++) {
            System.arraycopy(header, i * header_size + offset, des, 0, header_size);
            type_32.symList.add(parseSymbolTable(des));
        }
    }

    private static ElfType32.Elf32_Sym parseSymbolTable(byte[] header) {
        /**
         *  public byte[] st_name = new byte[4];
         public byte[] st_value = new byte[4];
         public byte[] st_size = new byte[4];
         public byte st_info;
         public byte st_other;
         public byte[] st_shndx = new byte[2];
         */
        Elf32_Sym sym = new Elf32_Sym();
        sym.st_name = Utils.copyBytes(header, 0, 4);
        sym.st_value = Utils.copyBytes(header, 4, 4);
        sym.st_size = Utils.copyBytes(header, 8, 4);
        sym.st_info = header[12];
        //FIXME ������һ�����⣬��������ֶζ�������ֵʼ����0
        sym.st_other = header[13];
        sym.st_shndx = Utils.copyBytes(header, 14, 2);
        return sym;
    }

    /**
     * //��׼��hash����
     * static unsigned elfhash(const char *_name)
     * {
     * const unsigned char *name = (const unsigned char *) _name;
     * unsigned h = 0, g;
     * <p>
     * while(*name) {
     * h = (h << 4) + *name++;
     * g = h & 0xf0000000;
     * h ^= g;
     * h ^= g >> 24;
     * }
     * return h;
     * }
     *
     * @return
     */
    private static long elfhash(byte[] name) {
        if (name == null || name.length == 0) {
            return -1;
        }
        long h = 0, g;
        for (int i = 0; i < name.length; i++) {
            h = (h << 4) + name[i];
            g = h & 0xf0000000;
            h ^= g;
            h ^= (g >> 24);
        }
        return h;
    }

}
