//! Per-build NT system service tables.
//!
//! The raw number a user thread places in `rax` before `syscall` is not a
//! stable ABI: Microsoft renumbers services between releases. This module
//! separates the abstract service ([`NtService`]) from the raw number and
//! keeps one [`ServiceTable`] per supported Windows build ([`WindowsBuild`]).
//!
//! # Source
//!
//! Every number below comes from Mateusz Jurczyk's public x64 table,
//! <https://github.com/j00ru/windows-syscalls>, file `x64/csv/nt.csv`
//! (columns "Windows Server 2003 (SP2)", "Windows XP (SP2)", "Windows 7
//! (SP1)" and "Windows 10 (22H2)"). Only services present in that table for
//! the given build are listed; a service the table does not list for a build
//! is left out instead of guessed. Lookups therefore return `None` for it.
//!
//! Only the native (`ntoskrnl`) table is modelled. Numbers with bit 12 set
//! select the win32k shadow table and are never matched here.

/// An NT native system service, independent of its per-build number.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[repr(u16)]
pub enum NtService {
    /// `NtAllocateVirtualMemory`.
    AllocateVirtualMemory = 0,
    /// `NtClearEvent`.
    ClearEvent = 1,
    /// `NtClose`.
    Close = 2,
    /// `NtCreateEvent`.
    CreateEvent = 3,
    /// `NtCreateFile`.
    CreateFile = 4,
    /// `NtCreateSection`.
    CreateSection = 5,
    /// `NtCreateThreadEx` (absent before Windows Vista).
    CreateThreadEx = 6,
    /// `NtDelayExecution`.
    DelayExecution = 7,
    /// `NtDeviceIoControlFile`.
    DeviceIoControlFile = 8,
    /// `NtDuplicateObject`.
    DuplicateObject = 9,
    /// `NtFreeVirtualMemory`.
    FreeVirtualMemory = 10,
    /// `NtMapViewOfSection`.
    MapViewOfSection = 11,
    /// `NtOpenEvent`.
    OpenEvent = 12,
    /// `NtOpenFile`.
    OpenFile = 13,
    /// `NtProtectVirtualMemory`.
    ProtectVirtualMemory = 14,
    /// `NtQueryInformationFile`.
    QueryInformationFile = 15,
    /// `NtQueryInformationProcess`.
    QueryInformationProcess = 16,
    /// `NtQueryObject`.
    QueryObject = 17,
    /// `NtQueryPerformanceCounter`.
    QueryPerformanceCounter = 18,
    /// `NtQuerySystemInformation`.
    QuerySystemInformation = 19,
    /// `NtQueryVirtualMemory`.
    QueryVirtualMemory = 20,
    /// `NtReadFile`.
    ReadFile = 21,
    /// `NtResetEvent`.
    ResetEvent = 22,
    /// `NtSetEvent`.
    SetEvent = 23,
    /// `NtSetInformationFile`.
    SetInformationFile = 24,
    /// `NtTerminateProcess`.
    TerminateProcess = 25,
    /// `NtTerminateThread`.
    TerminateThread = 26,
    /// `NtUnmapViewOfSection`.
    UnmapViewOfSection = 27,
    /// `NtWaitForMultipleObjects`.
    WaitForMultipleObjects = 28,
    /// `NtWaitForSingleObject`.
    WaitForSingleObject = 29,
    /// `NtWriteFile`.
    WriteFile = 30,
    /// `NtYieldExecution`.
    YieldExecution = 31,
}

impl NtService {
    /// Number of abstract services.
    pub const COUNT: usize = 32;

    /// Every abstract service, in discriminant order.
    pub const ALL: [Self; Self::COUNT] = [
        Self::AllocateVirtualMemory,
        Self::ClearEvent,
        Self::Close,
        Self::CreateEvent,
        Self::CreateFile,
        Self::CreateSection,
        Self::CreateThreadEx,
        Self::DelayExecution,
        Self::DeviceIoControlFile,
        Self::DuplicateObject,
        Self::FreeVirtualMemory,
        Self::MapViewOfSection,
        Self::OpenEvent,
        Self::OpenFile,
        Self::ProtectVirtualMemory,
        Self::QueryInformationFile,
        Self::QueryInformationProcess,
        Self::QueryObject,
        Self::QueryPerformanceCounter,
        Self::QuerySystemInformation,
        Self::QueryVirtualMemory,
        Self::ReadFile,
        Self::ResetEvent,
        Self::SetEvent,
        Self::SetInformationFile,
        Self::TerminateProcess,
        Self::TerminateThread,
        Self::UnmapViewOfSection,
        Self::WaitForMultipleObjects,
        Self::WaitForSingleObject,
        Self::WriteFile,
        Self::YieldExecution,
    ];

    /// The exported `ntdll` name of the service.
    pub const fn name(self) -> &'static str {
        match self {
            Self::AllocateVirtualMemory => "NtAllocateVirtualMemory",
            Self::ClearEvent => "NtClearEvent",
            Self::Close => "NtClose",
            Self::CreateEvent => "NtCreateEvent",
            Self::CreateFile => "NtCreateFile",
            Self::CreateSection => "NtCreateSection",
            Self::CreateThreadEx => "NtCreateThreadEx",
            Self::DelayExecution => "NtDelayExecution",
            Self::DeviceIoControlFile => "NtDeviceIoControlFile",
            Self::DuplicateObject => "NtDuplicateObject",
            Self::FreeVirtualMemory => "NtFreeVirtualMemory",
            Self::MapViewOfSection => "NtMapViewOfSection",
            Self::OpenEvent => "NtOpenEvent",
            Self::OpenFile => "NtOpenFile",
            Self::ProtectVirtualMemory => "NtProtectVirtualMemory",
            Self::QueryInformationFile => "NtQueryInformationFile",
            Self::QueryInformationProcess => "NtQueryInformationProcess",
            Self::QueryObject => "NtQueryObject",
            Self::QueryPerformanceCounter => "NtQueryPerformanceCounter",
            Self::QuerySystemInformation => "NtQuerySystemInformation",
            Self::QueryVirtualMemory => "NtQueryVirtualMemory",
            Self::ReadFile => "NtReadFile",
            Self::ResetEvent => "NtResetEvent",
            Self::SetEvent => "NtSetEvent",
            Self::SetInformationFile => "NtSetInformationFile",
            Self::TerminateProcess => "NtTerminateProcess",
            Self::TerminateThread => "NtTerminateThread",
            Self::UnmapViewOfSection => "NtUnmapViewOfSection",
            Self::WaitForMultipleObjects => "NtWaitForMultipleObjects",
            Self::WaitForSingleObject => "NtWaitForSingleObject",
            Self::WriteFile => "NtWriteFile",
            Self::YieldExecution => "NtYieldExecution",
        }
    }

    /// Decode an abstract service index from an untrusted integer.
    pub const fn from_raw(raw: u16) -> Option<Self> {
        if (raw as usize) < Self::COUNT {
            Some(Self::ALL[raw as usize])
        } else {
            None
        }
    }
}

/// A Windows release and build whose x64 service numbering is modelled.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum WindowsBuild {
    /// Windows Server 2003 SP2 and Windows XP Professional x64 Edition SP2,
    /// which share NT build 3790 and the same service table.
    Server2003Sp2,
    /// Windows 7 SP1 / Server 2008 R2 SP1, NT build 7601.
    Windows7Sp1,
    /// Windows 10 22H2, NT build 19045.
    Windows10_22H2,
}

impl WindowsBuild {
    /// Every modelled build, oldest first.
    pub const ALL: [Self; 3] = [Self::Server2003Sp2, Self::Windows7Sp1, Self::Windows10_22H2];

    /// The NT build number reported by `RtlGetVersion`.
    pub const fn build_number(self) -> u32 {
        match self {
            Self::Server2003Sp2 => 3790,
            Self::Windows7Sp1 => 7601,
            Self::Windows10_22H2 => 19045,
        }
    }

    /// Select a modelled build from an untrusted build number.
    ///
    /// Only exact matches are accepted: neighbouring builds may renumber
    /// services, so no nearest-build fallback is attempted.
    pub const fn from_build_number(build: u32) -> Option<Self> {
        match build {
            3790 => Some(Self::Server2003Sp2),
            7601 => Some(Self::Windows7Sp1),
            19045 => Some(Self::Windows10_22H2),
            _ => None,
        }
    }

    /// The x64 native service table of this build.
    pub const fn service_table(self) -> &'static ServiceTable {
        match self {
            Self::Server2003Sp2 => &SERVER_2003_SP2_X64,
            Self::Windows7Sp1 => &WINDOWS_7_SP1_X64,
            Self::Windows10_22H2 => &WINDOWS_10_22H2_X64,
        }
    }
}

/// One service-number binding in a [`ServiceTable`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceEntry {
    /// The raw number placed in `eax` before `syscall`.
    pub number: u16,
    /// The abstract service it selects.
    pub service: NtService,
}

const fn entry(number: u16, service: NtService) -> ServiceEntry {
    ServiceEntry { number, service }
}

/// Reasons a service table is rejected by [`ServiceTable::validate`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TableError {
    /// Two entries use the same raw number.
    DuplicateNumber(u16),
    /// One service is bound to more than one raw number.
    DuplicateService(NtService),
    /// A number lies outside the 12-bit native table index.
    NumberOutOfRange(u16),
}

/// Raw service numbers index the native table with their low 12 bits; higher
/// bits select another table, so a native number must be below this bound.
pub const NATIVE_INDEX_LIMIT: u16 = 0x1000;

/// A per-build mapping between raw service numbers and [`NtService`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceTable {
    build: WindowsBuild,
    entries: &'static [ServiceEntry],
}

impl ServiceTable {
    /// The build this table describes.
    pub const fn build(&self) -> WindowsBuild {
        self.build
    }

    /// All bindings of this table.
    pub const fn entries(&self) -> &'static [ServiceEntry] {
        self.entries
    }

    /// Resolve an untrusted raw service number (the full `rax` value).
    ///
    /// Any value that does not exactly equal a listed number, including one
    /// with stray upper bits, is rejected.
    pub const fn service(&self, raw: u64) -> Option<NtService> {
        let mut index = 0;
        while index < self.entries.len() {
            let entry = self.entries[index];
            if entry.number as u64 == raw {
                return Some(entry.service);
            }
            index += 1;
        }
        None
    }

    /// The raw number of `service` in this build, if the build has it.
    pub const fn number(&self, service: NtService) -> Option<u16> {
        let mut index = 0;
        while index < self.entries.len() {
            let entry = self.entries[index];
            if entry.service as u16 == service as u16 {
                return Some(entry.number);
            }
            index += 1;
        }
        None
    }

    /// Check that numbers and services are each bound at most once and every
    /// number is a native-table index.
    pub const fn validate(&self) -> Result<(), TableError> {
        let entries = self.entries;
        let mut i = 0;
        while i < entries.len() {
            if entries[i].number >= NATIVE_INDEX_LIMIT {
                return Err(TableError::NumberOutOfRange(entries[i].number));
            }
            let mut j = i + 1;
            while j < entries.len() {
                if entries[i].number == entries[j].number {
                    return Err(TableError::DuplicateNumber(entries[i].number));
                }
                if entries[i].service as u16 == entries[j].service as u16 {
                    return Err(TableError::DuplicateService(entries[i].service));
                }
                j += 1;
            }
            i += 1;
        }
        Ok(())
    }
}

/// Windows Server 2003 SP2 / XP x64 SP2, build 3790.
///
/// Source: j00ru/windows-syscalls `x64/csv/nt.csv`, columns "Windows Server
/// 2003 (SP2)" and "Windows XP (SP2)", which agree for every entry here.
/// `NtCreateThreadEx` does not exist in this build.
pub static SERVER_2003_SP2_X64: ServiceTable = ServiceTable {
    build: WindowsBuild::Server2003Sp2,
    entries: &[
        entry(0x0001, NtService::WaitForSingleObject),
        entry(0x0003, NtService::ReadFile),
        entry(0x0004, NtService::DeviceIoControlFile),
        entry(0x0005, NtService::WriteFile),
        entry(0x000b, NtService::SetEvent),
        entry(0x000c, NtService::Close),
        entry(0x000d, NtService::QueryObject),
        entry(0x000e, NtService::QueryInformationFile),
        entry(0x0015, NtService::AllocateVirtualMemory),
        entry(0x0016, NtService::QueryInformationProcess),
        entry(0x001b, NtService::FreeVirtualMemory),
        entry(0x0020, NtService::QueryVirtualMemory),
        entry(0x0024, NtService::SetInformationFile),
        entry(0x0025, NtService::MapViewOfSection),
        entry(0x0027, NtService::UnmapViewOfSection),
        entry(0x0029, NtService::TerminateProcess),
        entry(0x002e, NtService::QueryPerformanceCounter),
        entry(0x0030, NtService::OpenFile),
        entry(0x0031, NtService::DelayExecution),
        entry(0x0033, NtService::QuerySystemInformation),
        entry(0x0039, NtService::DuplicateObject),
        entry(0x003b, NtService::ClearEvent),
        entry(0x003d, NtService::OpenEvent),
        entry(0x0043, NtService::YieldExecution),
        entry(0x0045, NtService::CreateEvent),
        entry(0x0047, NtService::CreateSection),
        entry(0x004d, NtService::ProtectVirtualMemory),
        entry(0x0050, NtService::TerminateThread),
        entry(0x0052, NtService::CreateFile),
        entry(0x0058, NtService::WaitForMultipleObjects),
        entry(0x00ec, NtService::ResetEvent),
    ],
};

/// Windows 7 SP1, build 7601.
///
/// Source: j00ru/windows-syscalls `x64/csv/nt.csv`, column "Windows 7 (SP1)".
pub static WINDOWS_7_SP1_X64: ServiceTable = ServiceTable {
    build: WindowsBuild::Windows7Sp1,
    entries: &[
        entry(0x0001, NtService::WaitForSingleObject),
        entry(0x0003, NtService::ReadFile),
        entry(0x0004, NtService::DeviceIoControlFile),
        entry(0x0005, NtService::WriteFile),
        entry(0x000b, NtService::SetEvent),
        entry(0x000c, NtService::Close),
        entry(0x000d, NtService::QueryObject),
        entry(0x000e, NtService::QueryInformationFile),
        entry(0x0015, NtService::AllocateVirtualMemory),
        entry(0x0016, NtService::QueryInformationProcess),
        entry(0x001b, NtService::FreeVirtualMemory),
        entry(0x0020, NtService::QueryVirtualMemory),
        entry(0x0024, NtService::SetInformationFile),
        entry(0x0025, NtService::MapViewOfSection),
        entry(0x0027, NtService::UnmapViewOfSection),
        entry(0x0029, NtService::TerminateProcess),
        entry(0x002e, NtService::QueryPerformanceCounter),
        entry(0x0030, NtService::OpenFile),
        entry(0x0031, NtService::DelayExecution),
        entry(0x0033, NtService::QuerySystemInformation),
        entry(0x0039, NtService::DuplicateObject),
        entry(0x003b, NtService::ClearEvent),
        entry(0x003d, NtService::OpenEvent),
        entry(0x0043, NtService::YieldExecution),
        entry(0x0045, NtService::CreateEvent),
        entry(0x0047, NtService::CreateSection),
        entry(0x004d, NtService::ProtectVirtualMemory),
        entry(0x0050, NtService::TerminateThread),
        entry(0x0052, NtService::CreateFile),
        entry(0x0058, NtService::WaitForMultipleObjects),
        entry(0x00a5, NtService::CreateThreadEx),
        entry(0x0141, NtService::ResetEvent),
    ],
};

/// Windows 10 22H2, build 19045.
///
/// Source: j00ru/windows-syscalls `x64/csv/nt.csv`, column "Windows 10
/// (22H2)".
pub static WINDOWS_10_22H2_X64: ServiceTable = ServiceTable {
    build: WindowsBuild::Windows10_22H2,
    entries: &[
        entry(0x0004, NtService::WaitForSingleObject),
        entry(0x0006, NtService::ReadFile),
        entry(0x0007, NtService::DeviceIoControlFile),
        entry(0x0008, NtService::WriteFile),
        entry(0x000e, NtService::SetEvent),
        entry(0x000f, NtService::Close),
        entry(0x0010, NtService::QueryObject),
        entry(0x0011, NtService::QueryInformationFile),
        entry(0x0018, NtService::AllocateVirtualMemory),
        entry(0x0019, NtService::QueryInformationProcess),
        entry(0x001e, NtService::FreeVirtualMemory),
        entry(0x0023, NtService::QueryVirtualMemory),
        entry(0x0027, NtService::SetInformationFile),
        entry(0x0028, NtService::MapViewOfSection),
        entry(0x002a, NtService::UnmapViewOfSection),
        entry(0x002c, NtService::TerminateProcess),
        entry(0x0031, NtService::QueryPerformanceCounter),
        entry(0x0033, NtService::OpenFile),
        entry(0x0034, NtService::DelayExecution),
        entry(0x0036, NtService::QuerySystemInformation),
        entry(0x003c, NtService::DuplicateObject),
        entry(0x003e, NtService::ClearEvent),
        entry(0x0040, NtService::OpenEvent),
        entry(0x0046, NtService::YieldExecution),
        entry(0x0048, NtService::CreateEvent),
        entry(0x004a, NtService::CreateSection),
        entry(0x0050, NtService::ProtectVirtualMemory),
        entry(0x0053, NtService::TerminateThread),
        entry(0x0055, NtService::CreateFile),
        entry(0x005b, NtService::WaitForMultipleObjects),
        entry(0x00c2, NtService::CreateThreadEx),
        entry(0x017a, NtService::ResetEvent),
    ],
};

// Reject a malformed table at compile time, not on first use.
const _: () = {
    assert!(SERVER_2003_SP2_X64.validate().is_ok());
    assert!(WINDOWS_7_SP1_X64.validate().is_ok());
    assert!(WINDOWS_10_22H2_X64.validate().is_ok());
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_indices_round_trip() {
        for (index, service) in NtService::ALL.iter().enumerate() {
            assert_eq!(*service as usize, index);
            assert_eq!(NtService::from_raw(index as u16), Some(*service));
            assert!(service.name().starts_with("Nt"));
        }
        assert_eq!(NtService::from_raw(NtService::COUNT as u16), None);
        assert_eq!(NtService::from_raw(u16::MAX), None);
    }

    #[test]
    fn builds_round_trip_and_reject_neighbours() {
        for build in WindowsBuild::ALL {
            assert_eq!(
                WindowsBuild::from_build_number(build.build_number()),
                Some(build)
            );
            assert_eq!(build.service_table().build(), build);
        }
        for near in [0, 2600, 3791, 7600, 9200, 19044, 22000, u32::MAX] {
            assert_eq!(WindowsBuild::from_build_number(near), None);
        }
    }

    #[test]
    fn every_table_validates() {
        for build in WindowsBuild::ALL {
            assert_eq!(build.service_table().validate(), Ok(()));
        }
    }

    #[test]
    fn lookups_agree_in_both_directions() {
        for build in WindowsBuild::ALL {
            let table = build.service_table();
            for entry in table.entries() {
                assert_eq!(table.service(entry.number as u64), Some(entry.service));
                assert_eq!(table.number(entry.service), Some(entry.number));
            }
        }
    }

    #[test]
    fn requested_services_are_present_in_every_build() {
        let required = [
            NtService::Close,
            NtService::CreateFile,
            NtService::OpenFile,
            NtService::ReadFile,
            NtService::WriteFile,
            NtService::AllocateVirtualMemory,
            NtService::FreeVirtualMemory,
            NtService::ProtectVirtualMemory,
            NtService::QueryVirtualMemory,
            NtService::TerminateProcess,
            NtService::CreateEvent,
            NtService::SetEvent,
            NtService::WaitForSingleObject,
            NtService::QuerySystemInformation,
            NtService::QueryInformationProcess,
            NtService::CreateSection,
            NtService::MapViewOfSection,
            NtService::UnmapViewOfSection,
        ];
        for build in WindowsBuild::ALL {
            for service in required {
                assert!(build.service_table().number(service).is_some());
            }
        }
    }

    #[test]
    fn known_numbers_match_the_source_table() {
        let xp = &SERVER_2003_SP2_X64;
        let win7 = &WINDOWS_7_SP1_X64;
        let win10 = &WINDOWS_10_22H2_X64;
        assert_eq!(xp.number(NtService::Close), Some(0x0c));
        assert_eq!(win7.number(NtService::Close), Some(0x0c));
        assert_eq!(win10.number(NtService::Close), Some(0x0f));
        assert_eq!(win7.number(NtService::CreateFile), Some(0x52));
        assert_eq!(win10.number(NtService::CreateFile), Some(0x55));
        assert_eq!(win7.service(0x29), Some(NtService::TerminateProcess));
        assert_eq!(win10.service(0x2c), Some(NtService::TerminateProcess));
        // 0x29 is NtAccessCheckAndAuditAlarm on Windows 10, which is not
        // modelled, so it must not resolve to anything.
        assert_eq!(win10.service(0x29), None);
    }

    #[test]
    fn services_absent_from_a_build_are_not_guessed() {
        assert_eq!(SERVER_2003_SP2_X64.number(NtService::CreateThreadEx), None);
        assert_eq!(
            WINDOWS_7_SP1_X64.number(NtService::CreateThreadEx),
            Some(0xa5)
        );
    }

    #[test]
    fn hostile_raw_numbers_are_rejected() {
        for build in WindowsBuild::ALL {
            let table = build.service_table();
            let close = table.number(NtService::Close).unwrap() as u64;
            assert_eq!(table.service(close | 1 << 32), None);
            assert_eq!(table.service(close | 0x1000), None);
            assert_eq!(table.service(u64::MAX), None);
            assert_eq!(table.service(0xfff), None);
        }
    }

    #[test]
    fn validation_reports_each_defect() {
        static DUPLICATE_NUMBER: ServiceTable = ServiceTable {
            build: WindowsBuild::Windows7Sp1,
            entries: &[
                entry(0x0c, NtService::Close),
                entry(0x0c, NtService::ReadFile),
            ],
        };
        static DUPLICATE_SERVICE: ServiceTable = ServiceTable {
            build: WindowsBuild::Windows7Sp1,
            entries: &[entry(0x0c, NtService::Close), entry(0x0f, NtService::Close)],
        };
        static OUT_OF_RANGE: ServiceTable = ServiceTable {
            build: WindowsBuild::Windows7Sp1,
            entries: &[entry(0x1000, NtService::Close)],
        };
        assert_eq!(
            DUPLICATE_NUMBER.validate(),
            Err(TableError::DuplicateNumber(0x0c))
        );
        assert_eq!(
            DUPLICATE_SERVICE.validate(),
            Err(TableError::DuplicateService(NtService::Close))
        );
        assert_eq!(
            OUT_OF_RANGE.validate(),
            Err(TableError::NumberOutOfRange(0x1000))
        );
    }
}
