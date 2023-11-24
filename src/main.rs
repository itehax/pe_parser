#![allow(unused)]

use std::env;
use std::ffi::CStr;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::mem;
use windows::Win32::System::Diagnostics::Debug::{
    IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DIRECTORY_ENTRY_IAT, IMAGE_DIRECTORY_ENTRY_IMPORT,
    IMAGE_DIRECTORY_ENTRY_RESOURCE, IMAGE_FILE_HEADER, IMAGE_NT_HEADERS32, IMAGE_NT_HEADERS64,
    IMAGE_NT_OPTIONAL_HDR32_MAGIC, IMAGE_NT_OPTIONAL_HDR64_MAGIC, IMAGE_OPTIONAL_HEADER_MAGIC,
    IMAGE_SECTION_HEADER,
};
use windows::Win32::System::SystemServices::{
    IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_EXPORT_DIRECTORY, IMAGE_IMPORT_BY_NAME,
    IMAGE_IMPORT_DESCRIPTOR,
};
use windows::Win32::System::WindowsProgramming::{IMAGE_THUNK_DATA32, IMAGE_THUNK_DATA64};

fn main() {
    let file_path = env::args()
        .nth(1)
        .expect("Unable to get the file to parse.");

    let mut pe = PE::new(file_path);
    if !pe.is_valid() {
        panic!("Invalid pe type")
    }
    pe.dump_dos_header();

    pe.seek_magic();
    pe.get_pe_type();

    pe.seek_image_nt_header();
    pe.dump_nt_header();

    pe.dump_sections();

    pe.dump_import();
    pe.dump_export();
}

struct PE {
    pe_type: PEType,
    file: File,
    image_dos_header: IMAGE_DOS_HEADER,
    image_nt_headers_32: IMAGE_NT_HEADERS32,
    image_nt_headers_64: IMAGE_NT_HEADERS64,
    sections: Vec<IMAGE_SECTION_HEADER>,
    import_section: IMAGE_SECTION_HEADER,
    export_section: IMAGE_SECTION_HEADER,
}

impl PE {
    fn new(file_path: String) -> PE {
        PE {
            pe_type: Default::default(),
            file: File::open(file_path).expect("Unable to open the pe file to parse."),
            image_dos_header: IMAGE_DOS_HEADER::default(),
            image_nt_headers_32: IMAGE_NT_HEADERS32::default(),
            image_nt_headers_64: IMAGE_NT_HEADERS64::default(),
            sections: Default::default(),
            import_section: IMAGE_SECTION_HEADER::default(),
            export_section: IMAGE_SECTION_HEADER::default(),
        }
    }
    fn is_valid(&mut self) -> bool {
        fill_struct_from_file(&mut self.image_dos_header, &mut self.file);

        if self.image_dos_header.e_magic != IMAGE_DOS_SIGNATURE {
            return false;
        }
        true
    }
    fn dump_dos_header(&self) {
        println!("Dos Header:");
        println!("    magic -> {:#x}", self.image_dos_header.e_magic);
        let lfnanew = self.image_dos_header.e_lfanew;
        println!("    address of the pe file header -> {:#x}", lfnanew);
    }
    fn seek_magic(&mut self) {
        let _magic_pos = self
            .file
            .seek(SeekFrom::Start(
                self.image_dos_header.e_lfanew as u64
                    + mem::size_of::<IMAGE_FILE_HEADER>() as u64
                    + mem::size_of::<u32>() as u64, //size of pe signature
            ))
            .expect("Unable to seek magic pe value in the file");
    }
    fn get_pe_type(&mut self) {
        let mut pe_type = IMAGE_OPTIONAL_HEADER_MAGIC::default();
        fill_struct_from_file(&mut pe_type, &mut self.file);

        match pe_type {
            IMAGE_NT_OPTIONAL_HDR32_MAGIC => {
                self.pe_type = PEType::PE32;
            }
            IMAGE_NT_OPTIONAL_HDR64_MAGIC => {
                self.pe_type = PEType::PE64;
            }
            _ => panic!("Invalid pe type"),
        }
    }
    fn seek_image_nt_header(&mut self) {
        let _image_nt_header_pos = self
            .file
            .seek(SeekFrom::Start(self.image_dos_header.e_lfanew as u64))
            .expect("Unable to seek image_nt_header structure in the file");
    }

    fn dump_nt_header(&mut self) {
        match self.pe_type {
            PEType::PE32 => {
                println!("Pe 32");
                fill_struct_from_file(&mut self.image_nt_headers_32, &mut self.file);

                println!("Image Nt Headers 32:");
                println!(
                    "    Pe Signature -> {:#x}\n",
                    self.image_nt_headers_32.Signature
                );

                println!("File Header:");
                println!(
                    "    Machine -> {:#x}",
                    self.image_nt_headers_32.FileHeader.Machine.0
                );
                println!(
                    "    section count -> {:#x}",
                    self.image_nt_headers_32.FileHeader.NumberOfSections
                );
                println!(
                    "    time date stamp -> {:#x}",
                    self.image_nt_headers_32.FileHeader.TimeDateStamp
                );
                println!(
                    "    pointer to simble table -> {:#x}",
                    self.image_nt_headers_32.FileHeader.PointerToSymbolTable
                );
                println!(
                    "    num of simbles -> {:#x}",
                    self.image_nt_headers_32.FileHeader.NumberOfSymbols
                );
                println!(
                    "    size of optional headers -> {:#x}",
                    self.image_nt_headers_32.FileHeader.SizeOfOptionalHeader
                );
                println!(
                    "    characteristics -> {:#x}\n",
                    self.image_nt_headers_32.FileHeader.Characteristics.0
                );

                println!("Optional Header:");
                println!(
                    "    Magic -> {:#x}",
                    self.image_nt_headers_32.OptionalHeader.Magic.0
                );
                println!(
                    "    Major Linker Version -> {:#x}",
                    self.image_nt_headers_32.OptionalHeader.MajorLinkerVersion
                );
                println!(
                    "    Minor Linker Version -> {:#x}",
                    self.image_nt_headers_32.OptionalHeader.MinorLinkerVersion
                );
                println!(
                    "    Size Of Code -> {:#x}",
                    self.image_nt_headers_32.OptionalHeader.SizeOfCode
                );
                println!(
                    "    Size Of Initialized Data -> {:#x}",
                    self.image_nt_headers_32
                        .OptionalHeader
                        .SizeOfInitializedData
                );
                println!(
                    "    Size Of Uninitialized Data -> {:#x}",
                    self.image_nt_headers_32
                        .OptionalHeader
                        .SizeOfUninitializedData
                );
                println!(
                    "    Address Of Entry Point -> {:#x}",
                    self.image_nt_headers_32.OptionalHeader.AddressOfEntryPoint
                );
                println!(
                    "    Base Of Code -> {:#x}",
                    self.image_nt_headers_32.OptionalHeader.BaseOfCode
                );
                let image_base = self.image_nt_headers_32.OptionalHeader.ImageBase;
                println!("    Image Base -> {:#x}", image_base);
                println!(
                    "    Section Alignment -> {:#x}",
                    self.image_nt_headers_32.OptionalHeader.SectionAlignment
                );
                println!(
                    "    File Alignment -> {:#x}",
                    self.image_nt_headers_32.OptionalHeader.FileAlignment
                );
                println!(
                    "    Major Operating System Version -> {:#x}",
                    self.image_nt_headers_32
                        .OptionalHeader
                        .MajorOperatingSystemVersion
                );
                println!(
                    "    Minor Operating System Version -> {:#x}",
                    self.image_nt_headers_32
                        .OptionalHeader
                        .MinorOperatingSystemVersion
                );
                println!(
                    "    Major Image Version -> {:#x}",
                    self.image_nt_headers_32.OptionalHeader.MajorImageVersion
                );
                println!(
                    "    Minor Image Version -> {:#x}",
                    self.image_nt_headers_32.OptionalHeader.MinorImageVersion
                );
                println!(
                    "    Major Subsystem Version -> {:#x}",
                    self.image_nt_headers_32
                        .OptionalHeader
                        .MajorSubsystemVersion
                );
                println!(
                    "    Minor Subsystem Version -> {:#x}",
                    self.image_nt_headers_32
                        .OptionalHeader
                        .MinorSubsystemVersion
                );
                println!(
                    "    Win32 Version Value -> {:#x}",
                    self.image_nt_headers_32.OptionalHeader.Win32VersionValue
                );
                println!(
                    "    Size Of Image -> {:#x}",
                    self.image_nt_headers_32.OptionalHeader.SizeOfImage
                );
                println!(
                    "    Size Of Headers -> {:#x}",
                    self.image_nt_headers_32.OptionalHeader.SizeOfHeaders
                );
                println!(
                    "    CheckSum -> {:#x}",
                    self.image_nt_headers_32.OptionalHeader.CheckSum
                );
                println!(
                    "    Subsystem -> {:#x}",
                    self.image_nt_headers_32.OptionalHeader.Subsystem.0
                );
                println!(
                    "    Dll Characteristics -> {:#x}",
                    self.image_nt_headers_32.OptionalHeader.DllCharacteristics.0
                );
                println!(
                    "    Number Of RVA And Sizes -> {:#x}\n",
                    self.image_nt_headers_32.OptionalHeader.NumberOfRvaAndSizes
                );

                println!("Data directory:");
                println!("    import directory:");
                println!(
                    "        Virtual address -> {:#x}",
                    self.image_nt_headers_32.OptionalHeader.DataDirectory
                        [IMAGE_DIRECTORY_ENTRY_IMPORT.0 as usize]
                        .VirtualAddress,
                );
                println!(
                    "        Size -> {:#x}",
                    self.image_nt_headers_32.OptionalHeader.DataDirectory
                        [IMAGE_DIRECTORY_ENTRY_IMPORT.0 as usize]
                        .Size
                );

                println!("    export directory:");
                println!(
                    "        Virtual address -> {:#x}",
                    self.image_nt_headers_32.OptionalHeader.DataDirectory
                        [IMAGE_DIRECTORY_ENTRY_EXPORT.0 as usize]
                        .VirtualAddress,
                );
                println!(
                    "        Size -> {:#x}",
                    self.image_nt_headers_32.OptionalHeader.DataDirectory
                        [IMAGE_DIRECTORY_ENTRY_EXPORT.0 as usize]
                        .Size
                );

                println!("    resource directory:");
                println!(
                    "        Virtual address -> {:#x}",
                    self.image_nt_headers_32.OptionalHeader.DataDirectory
                        [IMAGE_DIRECTORY_ENTRY_RESOURCE.0 as usize]
                        .VirtualAddress,
                );
                println!(
                    "        Size -> {:#x}",
                    self.image_nt_headers_32.OptionalHeader.DataDirectory
                        [IMAGE_DIRECTORY_ENTRY_RESOURCE.0 as usize]
                        .Size
                );

                println!("    iat:");
                println!(
                    "        Virtual address -> {:#x}",
                    self.image_nt_headers_32.OptionalHeader.DataDirectory
                        [IMAGE_DIRECTORY_ENTRY_IAT.0 as usize]
                        .VirtualAddress,
                );
                println!(
                    "        Size -> {:#x}\n",
                    self.image_nt_headers_32.OptionalHeader.DataDirectory
                        [IMAGE_DIRECTORY_ENTRY_IAT.0 as usize]
                        .Size
                );
            }
            PEType::PE64 => {
                println!("Pe 64");
                fill_struct_from_file(&mut self.image_nt_headers_64, &mut self.file);

                println!("Image Nt Headers 64:");
                println!(
                    "    Pe Signature -> {:#x}\n",
                    self.image_nt_headers_64.Signature
                );

                println!("File Header:");
                println!(
                    "    Machine -> {:#x}",
                    self.image_nt_headers_64.FileHeader.Machine.0
                );
                println!(
                    "    section count -> {:#x}",
                    self.image_nt_headers_64.FileHeader.NumberOfSections
                );
                println!(
                    "    time date stamp -> {:#x}",
                    self.image_nt_headers_64.FileHeader.TimeDateStamp
                );
                println!(
                    "    pointer to simble table -> {:#x}",
                    self.image_nt_headers_64.FileHeader.PointerToSymbolTable
                );
                println!(
                    "    num of simbles -> {:#x}",
                    self.image_nt_headers_64.FileHeader.NumberOfSymbols
                );
                println!(
                    "    size of optional headers -> {:#x}",
                    self.image_nt_headers_64.FileHeader.SizeOfOptionalHeader
                );
                println!(
                    "    characteristics -> {:#x}\n",
                    self.image_nt_headers_64.FileHeader.Characteristics.0
                );

                println!("Optional Header:");
                println!(
                    "    Magic -> {:#x}",
                    self.image_nt_headers_64.OptionalHeader.Magic.0
                );
                println!(
                    "    Major Linker Version -> {:#x}",
                    self.image_nt_headers_64.OptionalHeader.MajorLinkerVersion
                );
                println!(
                    "    Minor Linker Version -> {:#x}",
                    self.image_nt_headers_64.OptionalHeader.MinorLinkerVersion
                );
                println!(
                    "    Size Of Code -> {:#x}",
                    self.image_nt_headers_64.OptionalHeader.SizeOfCode
                );
                println!(
                    "    Size Of Initialized Data -> {:#x}",
                    self.image_nt_headers_64
                        .OptionalHeader
                        .SizeOfInitializedData
                );
                println!(
                    "    Size Of Uninitialized Data -> {:#x}",
                    self.image_nt_headers_64
                        .OptionalHeader
                        .SizeOfUninitializedData
                );
                println!(
                    "    Address Of Entry Point -> {:#x}",
                    self.image_nt_headers_64.OptionalHeader.AddressOfEntryPoint
                );
                println!(
                    "    Base Of Code -> {:#x}",
                    self.image_nt_headers_64.OptionalHeader.BaseOfCode
                );
                let image_base = self.image_nt_headers_64.OptionalHeader.ImageBase;
                println!("    Image Base -> {:#x}", image_base);
                println!(
                    "    Section Alignment -> {:#x}",
                    self.image_nt_headers_64.OptionalHeader.SectionAlignment
                );
                println!(
                    "    File Alignment -> {:#x}",
                    self.image_nt_headers_64.OptionalHeader.FileAlignment
                );
                println!(
                    "    Major Operating System Version -> {:#x}",
                    self.image_nt_headers_64
                        .OptionalHeader
                        .MajorOperatingSystemVersion
                );
                println!(
                    "    Minor Operating System Version -> {:#x}",
                    self.image_nt_headers_64
                        .OptionalHeader
                        .MinorOperatingSystemVersion
                );
                println!(
                    "    Major Image Version -> {:#x}",
                    self.image_nt_headers_64.OptionalHeader.MajorImageVersion
                );
                println!(
                    "    Minor Image Version -> {:#x}",
                    self.image_nt_headers_64.OptionalHeader.MinorImageVersion
                );
                println!(
                    "    Major Subsystem Version -> {:#x}",
                    self.image_nt_headers_64
                        .OptionalHeader
                        .MajorSubsystemVersion
                );
                println!(
                    "    Minor Subsystem Version -> {:#x}",
                    self.image_nt_headers_64
                        .OptionalHeader
                        .MinorSubsystemVersion
                );
                println!(
                    "    Win32 Version Value -> {:#x}",
                    self.image_nt_headers_64.OptionalHeader.Win32VersionValue
                );
                println!(
                    "    Size Of Image -> {:#x}",
                    self.image_nt_headers_64.OptionalHeader.SizeOfImage
                );
                println!(
                    "    Size Of Headers -> {:#x}",
                    self.image_nt_headers_64.OptionalHeader.SizeOfHeaders
                );
                println!(
                    "    CheckSum -> {:#x}",
                    self.image_nt_headers_64.OptionalHeader.CheckSum
                );
                println!(
                    "    Subsystem -> {:#x}",
                    self.image_nt_headers_64.OptionalHeader.Subsystem.0
                );
                println!(
                    "    Dll Characteristics -> {:#x}",
                    self.image_nt_headers_64.OptionalHeader.DllCharacteristics.0
                );
                println!(
                    "    Number Of RVA And Sizes -> {:#x}\n",
                    self.image_nt_headers_64.OptionalHeader.NumberOfRvaAndSizes
                );

                println!("Data directory:");
                println!("    import directory:");
                println!(
                    "        Virtual address -> {:#x}",
                    self.image_nt_headers_64.OptionalHeader.DataDirectory
                        [IMAGE_DIRECTORY_ENTRY_IMPORT.0 as usize]
                        .VirtualAddress,
                );
                println!(
                    "        Size -> {:#x}",
                    self.image_nt_headers_64.OptionalHeader.DataDirectory
                        [IMAGE_DIRECTORY_ENTRY_IMPORT.0 as usize]
                        .Size
                );

                println!("    export directory:");
                println!(
                    "        Virtual address -> {:#x}",
                    self.image_nt_headers_64.OptionalHeader.DataDirectory
                        [IMAGE_DIRECTORY_ENTRY_EXPORT.0 as usize]
                        .VirtualAddress,
                );
                println!(
                    "        Size -> {:#x}",
                    self.image_nt_headers_64.OptionalHeader.DataDirectory
                        [IMAGE_DIRECTORY_ENTRY_EXPORT.0 as usize]
                        .Size
                );

                println!("    resource directory:");
                println!(
                    "        Virtual address -> {:#x}",
                    self.image_nt_headers_64.OptionalHeader.DataDirectory
                        [IMAGE_DIRECTORY_ENTRY_RESOURCE.0 as usize]
                        .VirtualAddress,
                );
                println!(
                    "        Size -> {:#x}",
                    self.image_nt_headers_64.OptionalHeader.DataDirectory
                        [IMAGE_DIRECTORY_ENTRY_RESOURCE.0 as usize]
                        .Size
                );

                println!("    iat:");
                println!(
                    "        Virtual address -> {:#x}",
                    self.image_nt_headers_64.OptionalHeader.DataDirectory
                        [IMAGE_DIRECTORY_ENTRY_IAT.0 as usize]
                        .VirtualAddress,
                );
                println!(
                    "        Size -> {:#x}\n",
                    self.image_nt_headers_64.OptionalHeader.DataDirectory
                        [IMAGE_DIRECTORY_ENTRY_IAT.0 as usize]
                        .Size
                );
            }
        }
    }
    fn get_sections(&mut self) {
        let (import_rva, export_rva, number_of_sections) = match self.pe_type {
            PEType::PE32 => (
                self.image_nt_headers_32.OptionalHeader.DataDirectory
                    [IMAGE_DIRECTORY_ENTRY_IMPORT.0 as usize]
                    .VirtualAddress,
                self.image_nt_headers_32.OptionalHeader.DataDirectory
                    [IMAGE_DIRECTORY_ENTRY_EXPORT.0 as usize]
                    .VirtualAddress,
                self.image_nt_headers_32.FileHeader.NumberOfSections,
            ),
            PEType::PE64 => (
                self.image_nt_headers_64.OptionalHeader.DataDirectory
                    [IMAGE_DIRECTORY_ENTRY_IMPORT.0 as usize]
                    .VirtualAddress,
                self.image_nt_headers_64.OptionalHeader.DataDirectory
                    [IMAGE_DIRECTORY_ENTRY_EXPORT.0 as usize]
                    .VirtualAddress,
                self.image_nt_headers_64.FileHeader.NumberOfSections,
            ),
        };

        for i in 0..number_of_sections as usize {
            self.seek_nth_section(i);

            let mut section = IMAGE_SECTION_HEADER::default();
            fill_struct_from_file(&mut section, &mut self.file);
            //we want to check in which section the import directory is
            if import_rva >= section.VirtualAddress
                && import_rva < section.VirtualAddress + unsafe { section.Misc.VirtualSize }
            {
                self.import_section = section;
            }
            //we want to check in which section the export directory is
            if export_rva >= section.VirtualAddress
                && export_rva < section.VirtualAddress + unsafe { section.Misc.VirtualSize }
            {
                self.export_section = section;
            }

            self.sections.push(section);
        }
    }

    fn seek_nth_section(&mut self, nth: usize) {
        let image_nt_header_size = match self.pe_type {
            PEType::PE32 => mem::size_of::<IMAGE_NT_HEADERS32>(),
            PEType::PE64 => mem::size_of::<IMAGE_NT_HEADERS64>(),
        } as u64;

        let _nth_section_pos = self
            .file
            .seek(SeekFrom::Start(
                self.image_dos_header.e_lfanew as u64
                    + image_nt_header_size
                    + (nth * mem::size_of::<IMAGE_SECTION_HEADER>()) as u64,
            ))
            .expect("Unable to seek nth section in the file");
    }

    fn dump_sections(&mut self) {
        self.get_sections();

        println!("Sections header:");
        for section in &self.sections {
            let section_name =
                std::str::from_utf8(&section.Name).expect("Unable to get section name");
            println!("    {}", section_name);
            println!("        virtual address -> {:#x}", section.VirtualAddress);
            unsafe {
                println!("        virtual size -> {:#x}", section.Misc.VirtualSize);
            }
            println!(
                "        pointer to raw data -> {:#x}",
                section.PointerToRawData
            );
            println!("        size of raw data -> {:#x}", section.SizeOfRawData);
            println!(
                "        characteristics -> {:#x}\n",
                section.Characteristics.0
            );
        }
        let import_section_name =
            std::str::from_utf8(&self.import_section.Name).expect("Unable to get section name");
    }
    fn dump_import(&mut self) {
        let import_rva = match self.pe_type {
            PEType::PE32 => {
                self.image_nt_headers_32.OptionalHeader.DataDirectory
                    [IMAGE_DIRECTORY_ENTRY_IMPORT.0 as usize]
                    .VirtualAddress
            }
            PEType::PE64 => {
                self.image_nt_headers_64.OptionalHeader.DataDirectory
                    [IMAGE_DIRECTORY_ENTRY_IMPORT.0 as usize]
                    .VirtualAddress
            }
        };
        println!("Import:");
        let image_import_descriptor_offset = self.import_section.PointerToRawData
            + (import_rva - self.import_section.VirtualAddress);

        let mut import_directory_nth = 0;
        loop {
            self.seek_nth_import(image_import_descriptor_offset, import_directory_nth);
            let mut import_descriptor = IMAGE_IMPORT_DESCRIPTOR::default();
            fill_struct_from_file(&mut import_descriptor, &mut self.file);

            if import_descriptor.Name == 0 && import_descriptor.FirstThunk == 0 {
                break;
            }

            let import_name_raw = self.import_section.PointerToRawData
                + (import_descriptor.Name - self.import_section.VirtualAddress);

            let import_name = self.get_import_name(import_name_raw);
            println!("import -> {}", import_name);

            self.dump_thunk(import_descriptor);

            import_directory_nth += 1;
        }
    }

    fn seek_nth_import(
        &mut self,
        image_import_descriptor_offset: u32,
        import_directory_nth: usize,
    ) {
        self.file
            .seek(SeekFrom::Start(
                image_import_descriptor_offset as u64
                    + (mem::size_of::<IMAGE_IMPORT_DESCRIPTOR>() * import_directory_nth) as u64,
            ))
            .expect("Unable to seek image import offset");
    }

    fn seek_import_name(&mut self, import_name_raw: u32) -> BufReader<&File> {
        let mut buf_reader = BufReader::new(&self.file);
        buf_reader
            .seek(SeekFrom::Start(import_name_raw as u64))
            .expect("Unable to seek import name");
        buf_reader
    }

    fn get_import_name(&mut self, import_name_raw: u32) -> String {
        let mut buf_reader = self.seek_import_name(import_name_raw);
        read_cstring_from_file(buf_reader)
    }
    fn dump_thunk(&mut self, import_descriptor: IMAGE_IMPORT_DESCRIPTOR) {
        match self.pe_type {
            PEType::PE32 => {
                let mut f_counter = 0;
                loop {
                    let ilt_raw = self.import_section.PointerToRawData
                        + (unsafe { import_descriptor.Anonymous.OriginalFirstThunk }
                            - self.import_section.VirtualAddress)
                        + (f_counter * mem::size_of::<IMAGE_THUNK_DATA32>() as u32);

                    self.seek_thunk(ilt_raw);

                    let mut thunk_data = IMAGE_THUNK_DATA32::default();
                    fill_struct_from_file(&mut thunk_data, &mut self.file);

                    if unsafe {
                        thunk_data.u1.AddressOfData == 0
                            && thunk_data.u1.ForwarderString == 0
                            && thunk_data.u1.Function == 0
                            && thunk_data.u1.Ordinal == 0
                    } {
                        break;
                    }
                    if unsafe { thunk_data.u1.AddressOfData } & (1 as u32) << 31 == 1 {
                        println!("Ordinal -> {}", unsafe { thunk_data.u1.Ordinal });
                    } else {
                        let f_import_name_raw = self.import_section.PointerToRawData
                            + (unsafe { thunk_data.u1.AddressOfData }
                                - self.import_section.VirtualAddress)
                            + 2;

                        let name = self.get_f_name(f_import_name_raw);
                        println!("name -> {}", name);
                        println!("    function address in IAT -> {:#x}", unsafe {
                            thunk_data.u1.Function
                        });
                        println!("    function address in ILT -> {:#x}", unsafe {
                            thunk_data.u1.AddressOfData
                        });
                    }
                    f_counter += 1;
                }
            }
            PEType::PE64 => {
                let mut f_counter = 0;
                loop {
                    let ilt_raw = self.import_section.PointerToRawData
                        + (unsafe { import_descriptor.Anonymous.OriginalFirstThunk }
                            - self.import_section.VirtualAddress)
                        + (f_counter * mem::size_of::<IMAGE_THUNK_DATA64>() as u32);

                    self.seek_thunk(ilt_raw);

                    let mut ilt_data = IMAGE_THUNK_DATA64::default();
                    fill_struct_from_file(&mut ilt_data, &mut self.file);

                    if unsafe {
                        ilt_data.u1.AddressOfData == 0
                            && ilt_data.u1.ForwarderString == 0
                            && ilt_data.u1.Function == 0
                            && ilt_data.u1.Ordinal == 0
                    } {
                        break;
                    }
                    if unsafe { ilt_data.u1.AddressOfData } & (1 as u64) << 63 == 1 {
                        println!("Ordinal -> {}", unsafe { ilt_data.u1.Ordinal });
                    } else {
                        let f_import_name_raw = self.import_section.PointerToRawData
                            + (unsafe { ilt_data.u1.AddressOfData } as u32
                                - self.import_section.VirtualAddress)
                            + 2;

                        let name = self.get_f_name(f_import_name_raw);
                        println!("name -> {}", name);
                        println!("    iat function address -> {:#x}", unsafe {
                            ilt_data.u1.Function
                        });
                        println!("    function address -> {:#x}", unsafe {
                            ilt_data.u1.AddressOfData
                        });
                    }
                    f_counter += 1;
                }
            }
        }
    }

    fn get_f_name(&mut self, f_import_name_raw: u32) -> String {
        let buf_reader = self.seek_f_name(f_import_name_raw);
        read_cstring_from_file(buf_reader)
    }

    fn seek_f_name(&mut self, f_import_name_raw: u32) -> BufReader<&File> {
        let mut buf_reader = BufReader::new(&self.file);
        buf_reader
            .seek(SeekFrom::Start(f_import_name_raw as u64))
            .expect("Unable to seek name");
        buf_reader
    }

    fn seek_thunk(&mut self, ilt_raw: u32) {
        self.file
            .seek(SeekFrom::Start(ilt_raw as u64))
            .expect("Unable to seek import name");
    }

    fn dump_export(&mut self) {
        let export_rva = match self.pe_type {
            PEType::PE32 => {
                self.image_nt_headers_32.OptionalHeader.DataDirectory
                    [IMAGE_DIRECTORY_ENTRY_EXPORT.0 as usize]
                    .VirtualAddress
            }
            PEType::PE64 => {
                self.image_nt_headers_64.OptionalHeader.DataDirectory
                    [IMAGE_DIRECTORY_ENTRY_EXPORT.0 as usize]
                    .VirtualAddress
            }
        };

        if export_rva == 0 {
            println!("No exports found");
            return;
        }
        println!("Export:");
        let export_offset = self.export_section.PointerToRawData
            + (export_rva - self.export_section.VirtualAddress);

        self.seek_export(export_offset);

        let mut image_export = IMAGE_EXPORT_DIRECTORY::default();
        fill_struct_from_file(&mut image_export, &mut self.file);

        for i in 0..image_export.NumberOfNames {
            self.dump_export_name(image_export, i);

            self.dump_export_f_address(image_export, i);
        }
    }

    fn dump_export_f_address(&mut self, image_export: IMAGE_EXPORT_DIRECTORY, nth: u32) {
        let address_of_f_raw = self.export_section.PointerToRawData
            + (image_export.AddressOfFunctions - self.export_section.VirtualAddress)
            + (nth * mem::size_of::<u32>() as u32);
        self.seek_addr_export_f(address_of_f_raw);

        let mut address_of_f: u32 = 0;
        fill_struct_from_file(&mut address_of_f, &mut self.file);
        println!("    address -> {:x}", address_of_f);
    }

    fn dump_export_name(&mut self, image_export: IMAGE_EXPORT_DIRECTORY, nth: u32) {
        let export_name_raw = self.export_section.PointerToRawData
            + (image_export.AddressOfNames - self.export_section.VirtualAddress)
            + (nth * mem::size_of::<u32>() as u32);

        self.seek_export_name(export_name_raw);

        let mut name_address: u32 = 0;
        fill_struct_from_file(&mut name_address, &mut self.file);

        let name_raw = self.export_section.PointerToRawData
            + (name_address - self.export_section.VirtualAddress);

        let name = self.get_f_name(name_raw);
        println!("    name -> {}", name);
    }

    fn seek_addr_export_f(&mut self, address_of_f_raw: u32) {
        self.file
            .seek(SeekFrom::Start(address_of_f_raw as u64))
            .unwrap();
    }

    fn seek_export_name(&mut self, export_name_raw: u32) {
        self.file
            .seek(SeekFrom::Start(export_name_raw as u64))
            .expect("Unable to seek export name raw");
    }

    fn seek_export(&mut self, export_offset: u32) {
        self.file
            .seek(SeekFrom::Start(export_offset as u64))
            .expect("Unable to seek export table");
    }
}

fn read_cstring_from_file(mut buf_reader: BufReader<&File>) -> String {
    let mut import_name = vec![];
    buf_reader
        .read_until(b'\0', &mut import_name)
        .expect("Unable to read file until null character");

    CStr::from_bytes_until_nul(&import_name)
        .expect("Unable to convert bytes to cstr")
        .to_string_lossy()
        .to_string()
}

#[derive(Default)]
enum PEType {
    #[default]
    PE32,
    PE64,
}

impl PEType {
    fn new(file: &mut File) -> Option<PEType> {
        let mut pe_type = IMAGE_OPTIONAL_HEADER_MAGIC::default();
        fill_struct_from_file(&mut pe_type, file);

        match pe_type {
            IMAGE_NT_OPTIONAL_HDR32_MAGIC => Some(PEType::PE32),
            IMAGE_NT_OPTIONAL_HDR64_MAGIC => Some(PEType::PE64),
            _ => None,
        }
    }
}

fn fill_struct_from_file<T>(structure: &mut T, file: &mut File) {
    unsafe {
        let buffer =
            std::slice::from_raw_parts_mut(structure as *mut T as *mut u8, mem::size_of::<T>());
        file.read_exact(buffer)
            .expect("Unable to fill_struct_from_file");
    }
}
