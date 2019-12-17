$ErrorActionPreference = "Stop"

Add-Type -TypeDefinition @'
using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Text;
using System.Text.RegularExpressions;

namespace SetupAPI
{
    internal class NativeHelpers
    {
        // devpkey.h https://github.com/tpn/winsdk-10/blob/master/Include/10.0.10240.0/shared/devpkey.h
        public static Dictionary<Guid, Dictionary<UInt32, string>> DEVPROPKEY_NAME_MAP = new Dictionary<Guid, Dictionary<uint, string>>()
        {
            {
                new Guid(0xb725f130, 0x47ef, 0x101a, 0xa5, 0xf1, 0x02, 0x60, 0x8c, 0x9e, 0xeb, 0xac),
                new Dictionary<uint, string>() {
                    { 10, "DEVPKEY_NAME" },
                }
            },
            {
                new Guid(0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0),
                new Dictionary<uint, string>() {
                    { 2, "DEVPKEY_Device_DeviceDesc" },
                    { 3, "DEVPKEY_Device_HardwareIds" },
                    { 4, "DEVPKEY_Device_CompatibleIds" },
                    { 6, "DEVPKEY_Device_Service" },
                    { 9, "DEVPKEY_Device_Class" },
                    { 10, "DEVPKEY_Device_ClassGuid" },
                    { 11, "DEVPKEY_Device_Driver" },
                    { 12, "DEVPKEY_Device_ConfigFlags" },
                    { 13, "DEVPKEY_Device_Manufacturer" },
                    { 14, "DEVPKEY_Device_FriendlyName" },
                    { 15, "DEVPKEY_Device_LocationInfo" },
                    { 16, "DEVPKEY_Device_PDOName" },
                    { 17, "DEVPKEY_Device_Capabilities" },
                    { 18, "DEVPKEY_Device_UINumber" },
                    { 19, "DEVPKEY_Device_UpperFilters" },
                    { 20, "DEVPKEY_Device_LowerFilters" },
                    { 21, "DEVPKEY_Device_BusTypeGuid" },
                    { 22, "DEVPKEY_Device_LegacyBusType" },
                    { 23, "DEVPKEY_Device_BusNumber" },
                    { 24, "DEVPKEY_Device_EnumeratorName" },
                    { 25, "DEVPKEY_Device_Security" },
                    { 26, "DEVPKEY_Device_SecuritySDS" },
                    { 27, "DEVPKEY_Device_DevType" },
                    { 28, "DEVPKEY_Device_Exclusive" },
                    { 29, "DEVPKEY_Device_Characteristics" },
                    { 30, "DEVPKEY_Device_Address" },
                    { 31, "DEVPKEY_Device_UINumberDescFormat" },
                    { 32, "DEVPKEY_Device_PowerData" },
                    { 33, "DEVPKEY_Device_RemovalPolicy" },
                    { 34, "DEVPKEY_Device_RemovalPolicyDefault" },
                    { 35, "DEVPKEY_Device_RemovalPolicyOverride" },
                    { 36, "DEVPKEY_Device_InstallState" },
                    { 37, "DEVPKEY_Device_LocationPaths" },
                    { 38, "DEVPKEY_Device_BaseContainerId" },
                }
            },
            {
                new Guid(0x78c34fc8, 0x104a, 0x4aca, 0x9e, 0xa4, 0x52, 0x4d, 0x52, 0x99, 0x6e, 0x57),
                new Dictionary<uint, string>() {
                    { 39, "DEVPKEY_Device_Model" },
                    { 51, "DEVPKEY_DeviceContainer_Address" },
                    { 52, "DEVPKEY_DeviceContainer_DiscoveryMethod" },
                    { 53, "DEVPKEY_DeviceContainer_IsEncrypted" },
                    { 54, "DEVPKEY_DeviceContainer_IsAuthenticated" },
                    { 55, "DEVPKEY_DeviceContainer_IsConnected" },
                    { 56, "DEVPKEY_DeviceContainer_IsPaired" },
                    { 57, "DEVPKEY_DeviceContainer_Icon" },
                    { 65, "DEVPKEY_DeviceContainer_Version" },
                    { 66, "DEVPKEY_DeviceContainer_Last_Seen" },
                    { 67, "DEVPKEY_DeviceContainer_Last_Connected" },
                    { 68, "DEVPKEY_DeviceContainer_IsShowInDisconnectedState" },
                    { 70, "DEVPKEY_DeviceContainer_IsLocalMachine" },
                    { 71, "DEVPKEY_DeviceContainer_MetadataPath" },
                    { 72, "DEVPKEY_DeviceContainer_IsMetadataSearchInProgress" },
                    { 73, "DEVPKEY_DeviceContainer_MetadataChecksum" },
                    { 74, "DEVPKEY_DeviceContainer_IsNotInterestingForDisplay" },
                    { 76, "DEVPKEY_DeviceContainer_LaunchDeviceStageOnDeviceConnect" },
                    { 77, "DEVPKEY_DeviceContainer_LaunchDeviceStageFromExplorer" },
                    { 78, "DEVPKEY_DeviceContainer_BaselineExperienceId" },
                    { 79, "DEVPKEY_DeviceContainer_IsDeviceUniquelyIdentifiable" },
                    { 80, "DEVPKEY_DeviceContainer_AssociationArray" },
                    { 81, "DEVPKEY_DeviceContainer_DeviceDescription1" },
                    { 82, "DEVPKEY_DeviceContainer_DeviceDescription2" },
                    { 83, "DEVPKEY_DeviceContainer_HasProblem" },
                    { 84, "DEVPKEY_DeviceContainer_IsSharedDevice" },
                    { 85, "DEVPKEY_DeviceContainer_IsNetworkDevice" },
                    { 86, "DEVPKEY_DeviceContainer_IsDefaultDevice" },
                    { 87, "DEVPKEY_DeviceContainer_MetadataCabinet" },
                    { 88, "DEVPKEY_DeviceContainer_RequiresPairingElevation" },
                    { 89, "DEVPKEY_DeviceContainer_ExperienceId" },
                    { 90, "DEVPKEY_DeviceContainer_Category" },
                    { 91, "DEVPKEY_DeviceContainer_Category_Desc_Singular" },
                    { 92, "DEVPKEY_DeviceContainer_Category_Desc_Plural" },
                    { 93, "DEVPKEY_DeviceContainer_Category_Icon" },
                    { 94, "DEVPKEY_DeviceContainer_CategoryGroup_Desc" },
                    { 95, "DEVPKEY_DeviceContainer_CategoryGroup_Icon" },
                    { 97, "DEVPKEY_DeviceContainer_PrimaryCategory" },
                    { 98, "DEVPKEY_DeviceContainer_UnpairUninstall" },
                    { 99, "DEVPKEY_DeviceContainer_RequiresUninstallElevation" },
                    { 100, "DEVPKEY_DeviceContainer_DeviceFunctionSubRank" },
                    { 101, "DEVPKEY_DeviceContainer_AlwaysShowDeviceAsConnected" },
                    { 105, "DEVPKEY_DeviceContainer_ConfigFlags" },
                    { 106, "DEVPKEY_DeviceContainer_PrivilegedPackageFamilyNames" },
                    { 107, "DEVPKEY_DeviceContainer_CustomPrivilegedPackageFamilyNames" },
                    { 108, "DEVPKEY_DeviceContainer_IsRebootRequired" },
                    { 256, "DEVPKEY_Device_InstanceId" },
                }
            },
            {
                new Guid(0x4340a6c5, 0x93fa, 0x4706, 0x97, 0x2c, 0x7b, 0x64, 0x80, 0x08, 0xa5, 0xa7),
                new Dictionary<uint, string>() {
                    { 2, "DEVPKEY_Device_DevNodeStatus" },
                    { 3, "DEVPKEY_Device_ProblemCode" },
                    { 4, "DEVPKEY_Device_EjectionRelations" },
                    { 5, "DEVPKEY_Device_RemovalRelations" },
                    { 6, "DEVPKEY_Device_PowerRelations" },
                    { 7, "DEVPKEY_Device_BusRelations" },
                    { 8, "DEVPKEY_Device_Parent" },
                    { 9, "DEVPKEY_Device_Children" },
                    { 10, "DEVPKEY_Device_Siblings" },
                    { 11, "DEVPKEY_Device_TransportRelations" },
                    { 12, "DEVPKEY_Device_ProblemStatus" },
                }
            },
            {
                new Guid(0x80497100, 0x8c73, 0x48b9, 0xaa, 0xd9, 0xce, 0x38, 0x7e, 0x19, 0xc5, 0x6e),
                new Dictionary<uint, string>() {
                    { 2, "DEVPKEY_Device_Reported" },
                    { 3, "DEVPKEY_Device_Legacy" },
                }
            },
            {
                new Guid(0x8c7ed206, 0x3f8a, 0x4827, 0xb3, 0xab, 0xae, 0x9e, 0x1f, 0xae, 0xfc, 0x6c),
                new Dictionary<uint, string>() {
                    { 2, "DEVPKEY_Device_ContainerId" },
                    { 4, "DEVPKEY_Device_InLocalMachineContainer" },
                }
            },
            {
                new Guid(0x80d81ea6, 0x7473, 0x4b0c, 0x82, 0x16, 0xef, 0xc1, 0x1a, 0x2c, 0x4c, 0x8b),
                new Dictionary<uint, string>()
                {
                    { 2, "DEVPKEY_Device_ModelId" },
                    { 3, "DEVPKEY_Device_FriendlyNameAttributes" },
                    { 4, "DEVPKEY_Device_ManufacturerAttributes" },
                    { 5, "DEVPKEY_Device_PresenceNotForDevice" },
                    { 6, "DEVPKEY_Device_SignalStrength" },
                    { 7, "DEVPKEY_Device_IsAssociateableByUserAction" },
                    { 8, "DEVPKEY_Device_ShowInUninstallUI" },
                }
            },
            {
                new Guid(0x540b947e, 0x8b40, 0x45bc, 0xa8, 0xa2, 0x6a, 0x0b, 0x89, 0x4c, 0xbd, 0xa2),
                new Dictionary<uint, string>()
                {
                    { 1, "DEVPKEY_Device_Numa_Proximity_Domain" },
                    { 2, "DEVPKEY_Device_DHP_Rebalance_Policy" },
                    { 3, "DEVPKEY_Device_Numa_Node" },
                    { 4, "DEVPKEY_Device_BusReportedDeviceDesc" },
                    { 5, "DEVPKEY_Device_IsPresent" },
                    { 6, "DEVPKEY_Device_HasProblem" },
                    { 7, "DEVPKEY_Device_ConfigurationId" },
                    { 8, "DEVPKEY_Device_ReportedDeviceIdsHash" },
                    { 9, "DEVPKEY_Device_PhysicalDeviceLocation" },
                    { 10, "DEVPKEY_Device_BiosDeviceName" },
                    { 11, "DEVPKEY_Device_DriverProblemDesc" },
                    { 12, "DEVPKEY_Device_DebuggerSafe" },
                    { 13, "DEVPKEY_Device_PostInstallInProgress" },
                    { 14, "DEVPKEY_Device_Stack" },
                    { 15, "DEVPKEY_Device_ExtendedConfigurationIds" },
                    { 16, "DEVPKEY_Device_IsRebootRequired" },
                    { 17, "DEVPKEY_Device_FirmwareDate" },
                    { 18, "DEVPKEY_Device_FirmwareVersion" },
                    { 19, "DEVPKEY_Device_FirmwareRevision" },
                    { 20, "DEVPKEY_Device_DependencyProviders" },
                    { 21, "DEVPKEY_Device_DependencyDependents" },
                    { 22, "DEVPKEY_Device_SoftRestartSupported" },
                }
            },
            {
                new Guid(0x83da6326, 0x97a6, 0x4088, 0x94, 0x53, 0xa1, 0x92, 0x3f, 0x57, 0x3b, 0x29),
                new Dictionary<uint, string>()
                {
                    { 6, "DEVPKEY_Device_SessionId" },
                    { 9, "DEVPKEY_DeviceContainer_InstallInProgress" },
                    { 100, "DEVPKEY_Device_InstallDate" },
                    { 101, "DEVPKEY_Device_FirstInstallDate" },
                    { 102, "DEVPKEY_Device_LastArrivalDate" },
                    { 103, "DEVPKEY_Device_LastRemovalDate" },
                }
            },
            {
                new Guid(0xa8b865dd, 0x2e3d, 0x4094, 0xad, 0x97, 0xe5, 0x93, 0xa7, 0xc, 0x75, 0xd6),
                new Dictionary<uint, string>()
                {
                    { 2, "DEVPKEY_Device_DriverDate" },
                    { 3, "DEVPKEY_Device_DriverVersion" },
                    { 4, "DEVPKEY_Device_DriverDesc" },
                    { 5, "DEVPKEY_Device_DriverInfPath" },
                    { 6, "DEVPKEY_Device_DriverInfSection" },
                    { 7, "DEVPKEY_Device_DriverInfSectionExt" },
                    { 8, "DEVPKEY_Device_MatchingDeviceId" },
                    { 9, "DEVPKEY_Device_DriverProvider" },
                    { 10, "DEVPKEY_Device_DriverPropPageProvider" },
                    { 11, "DEVPKEY_Device_DriverCoInstallers" },
                    { 12, "DEVPKEY_Device_ResourcePickerTags" },
                    { 13, "DEVPKEY_Device_ResourcePickerExceptions" },
                    { 14, "DEVPKEY_Device_DriverRank" },
                    { 15, "DEVPKEY_Device_DriverLogoLevel" },
                    { 17, "DEVPKEY_Device_NoConnectSound" },
                    { 18, "DEVPKEY_Device_GenericDriverInstalled" },
                    { 19, "DEVPKEY_Device_AdditionalSoftwareRequested" },
                }
            },
            {
                new Guid(0xafd97640,  0x86a3, 0x4210, 0xb6, 0x7c, 0x28, 0x9c, 0x41, 0xaa, 0xbe, 0x55),
                new Dictionary<uint, string>()
                {
                    { 2, "DEVPKEY_Device_SafeRemovalRequired" },
                    { 3, "DEVPKEY_Device_SafeRemovalRequiredOverride" },
                }
            },
            {
                new Guid(0xcf73bb51, 0x3abf, 0x44a2, 0x85, 0xe0, 0x9a, 0x3d, 0xc7, 0xa1, 0x21, 0x32),
                new Dictionary<uint, string>()
                {
                    { 2, "DEVPKEY_DrvPkg_Model" },
                    { 3, "DEVPKEY_DrvPkg_VendorWebSite" },
                    { 4, "DEVPKEY_DrvPkg_DetailedDescription" },
                    { 5, "DEVPKEY_DrvPkg_DocumentationLink" },
                    { 6, "DEVPKEY_DrvPkg_Icon" },
                    { 7, "DEVPKEY_DrvPkg_BrandingIcon" },
                }
            },
            {
                new Guid(0x4321918b, 0xf69e, 0x470d, 0xa5, 0xde, 0x4d, 0x88, 0xc7, 0x5a, 0xd2, 0x4b),
                new Dictionary<uint, string>()
                {
                    { 19, "DEVPKEY_DeviceClass_UpperFilters" },
                    { 20, "DEVPKEY_DeviceClass_LowerFilters" },
                    { 25, "DEVPKEY_DeviceClass_Security" },
                    { 26, "DEVPKEY_DeviceClass_SecuritySDS" },
                    { 27, "DEVPKEY_DeviceClass_DevType" },
                    { 28, "DEVPKEY_DeviceClass_Exclusive" },
                    { 29, "DEVPKEY_DeviceClass_Characteristics" },
                }
            },
            {
                new Guid(0x259abffc, 0x50a7, 0x47ce, 0xaf, 0x8, 0x68, 0xc9, 0xa7, 0xd7, 0x33, 0x66),
                new Dictionary<uint, string>()
                {
                    { 2, "DEVPKEY_DeviceClass_Name" },
                    { 3, "DEVPKEY_DeviceClass_ClassName" },
                    { 4, "DEVPKEY_DeviceClass_Icon" },
                    { 5, "DEVPKEY_DeviceClass_ClassInstaller" },
                    { 6, "DEVPKEY_DeviceClass_PropPageProvider" },
                    { 7, "DEVPKEY_DeviceClass_NoInstallClass" },
                    { 8, "DEVPKEY_DeviceClass_NoDisplayClass" },
                    { 9, "DEVPKEY_DeviceClass_SilentInstall" },
                    { 10, "DEVPKEY_DeviceClass_NoUseClass" },
                    { 11, "DEVPKEY_DeviceClass_DefaultService" },
                    { 12, "DEVPKEY_DeviceClass_IconPath" },
                }
            },
            {
                new Guid(0xd14d3ef3, 0x66cf, 0x4ba2, 0x9d, 0x38, 0x0d, 0xdb, 0x37, 0xab, 0x47, 0x01),

                new Dictionary<uint, string>()
                {
                    { 2, "DEVPKEY_DeviceClass_DHPRebalanceOptOut" },
                }
            },
            {
                new Guid(0x713d1703, 0xa2e2, 0x49f5, 0x92, 0x14, 0x56, 0x47, 0x2e, 0xf3, 0xda, 0x5c),
                new Dictionary<uint, string>()
                {
                    { 2, "DEVPKEY_DeviceClass_ClassCoInstallers" },
                }
            },
            {
                new Guid(0x026e516e, 0xb814, 0x414b, 0x83, 0xcd, 0x85, 0x6d, 0x6f, 0xef, 0x48, 0x22),
                new Dictionary<uint, string>()
                {
                    { 2, "DEVPKEY_DeviceInterface_FriendlyName" },
                    { 3, "DEVPKEY_DeviceInterface_Enabled" },
                    { 4, "DEVPKEY_DeviceInterface_ClassGuid" },
                    { 5, "DEVPKEY_DeviceInterface_ReferenceString" },
                    { 6, "DEVPKEY_DeviceInterface_Restricted" },
                }
            },
            {
                new Guid(0x14c83a99, 0x0b3f, 0x44b7, 0xbe, 0x4c, 0xa1, 0x78, 0xd3, 0x99, 0x05, 0x64),
                new Dictionary<uint, string>()
                {
                    { 2, "DEVPKEY_DeviceInterfaceClass_DefaultInterface" },
                    { 3, "DEVPKEY_DeviceInterfaceClass_Name" },
                }
            },
            {
                new Guid(0x656A3BB3, 0xECC0, 0x43FD, 0x84, 0x77, 0x4A, 0xE0, 0x40, 0x4A, 0x96, 0xCD),
                new Dictionary<uint, string>()
                {
                    { 8192, "DEVPKEY_DeviceContainer_Manufacturer" },
                    { 8194, "DEVPKEY_DeviceContainer_ModelName" },
                    { 8195, "DEVPKEY_DeviceContainer_ModelNumber" },
                    { 12288, "DEVPKEY_DeviceContainer_FriendlyName" },
                }
            },
            {
                new Guid(0x13673f42, 0xa3d6, 0x49f6, 0xb4, 0xda, 0xae, 0x46, 0xe0, 0xc5, 0x23, 0x7c),
                new Dictionary<uint, string>()
                {
                    { 2, "DEVPKEY_DevQuery_ObjectType" },
                }
            },
        };

        [StructLayout(LayoutKind.Sequential)]
        public struct DEVPROPKEY
        {
            public Guid fmtid;
            public UInt32 pid;

            public override string ToString()
            {
                foreach (KeyValuePair<Guid, Dictionary<UInt32, string>> kvp in DEVPROPKEY_NAME_MAP)
                {
                    if (kvp.Key != this.fmtid)
                        continue;

                    if (kvp.Value.ContainsKey(this.pid))
                        return kvp.Value[this.pid];
                }

                // No match, just return "{Guid}[Id]"
                return String.Format("{{{0}}}[{1}]", this.fmtid.ToString(), this.pid);
            }

            public static DEVPROPKEY FromString(string s)
            {
                Guid fmtid = new Guid();
                UInt32 pid = 0;

                bool found = false;
                foreach (KeyValuePair<Guid, Dictionary<UInt32, string>> kvp in DEVPROPKEY_NAME_MAP)
                {
                    if (found)
                        break;

                    foreach (KeyValuePair<UInt32, string> typeKvp in kvp.Value)
                    {
                        if (typeKvp.Value == s)
                        {
                            fmtid = kvp.Key;
                            pid = typeKvp.Key;
                            found = true;
                            break;
                        }
                    }
                }

                if (!found)
                {
                    Match m = Regex.Match(s,
                        "(?i)\\{([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\\}" +
                        "\\[\\b([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\\b\\]");

                    if (!m.Success)
                        throw new ArgumentException("Invalid property key {0}", s);

                    fmtid = new Guid(m.Groups[1].ToString());
                    pid = UInt32.Parse(m.Groups[2].ToString());
                }

                return new DEVPROPKEY()
                {
                    fmtid = fmtid,
                    pid = pid,
                };
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public class SP_CLASSINSTALL_HEADER
        {
            public UInt32 cbSize;
            public DifCodes InstallFunction;

            public SP_CLASSINSTALL_HEADER()
            {
                this.cbSize = (UInt32)Marshal.SizeOf(this);
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public class SP_DEVINFO_DATA
        {
            public UInt32 cbSize;
            public Guid ClassGuid;
            public UInt32 DevInst;
            public UIntPtr Reserved;

            public SP_DEVINFO_DATA()
            {
                this.cbSize = (UInt32)Marshal.SizeOf(this);
                this.ClassGuid = Guid.Empty;
            }
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct SP_DEVINSTALL_PARAMS
        {
            public UInt32 cbSize;
            public InstallFlags Flags;
            public InstallFlagsEx FlagsEx;
            public IntPtr hwndParent;
            public IntPtr InstallMsgHandler;
            public IntPtr InstallMsgHandlerContext;
            public IntPtr FileQueue;
            public UIntPtr ClassInstallReserved;
            public UInt32 Reserved;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string DriverPath;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SP_PROPCHANGE_PARAMS
        {
            public SP_CLASSINSTALL_HEADER ClassInstallHeader;
            public PropertyState StateChange;
            public PropertyScope Scope;
            public UInt32 HwProfile;
        }

        public enum DifCodes : uint
        {
            DIF_SELECTDIVE = 0x00000001,
            DIF_INSTALLDEVICE = 0x00000002,
            DIF_ASSIGNRESOURCES = 0x00000003,
            DIF_PROPERTIES = 0x00000004,
            DIF_REMOVE = 0x00000005,
            DIF_FIRSTTIMESETUP = 0x00000006,
            DIF_FOUNDDEVICE = 0x00000007,
            DIF_SELECTCLASSDRIVERS = 0x00000008,
            DIF_VALIDATECLASSDRIVERS = 0x00000009,
            DIF_INSTALLCLASSDRIVERS = 0x0000000a,
            DIF_CALCDISKSPACE = 0x0000000b,
            DIF_DESTROYPRIVATEDATA = 0x0000000c,
            DIF_VALIDATEDRIVER = 0x0000000d,
            DIF_DETECT = 0x0000000f,
            DIF_INSTALLWIZARD = 0x00000010,
            DIF_DESTROYWIZARDDATA = 0x00000011,
            DIF_PROPERTYCHANGE = 0x00000012,
            DIF_ENABLECLASS = 0x00000013,
            DIF_DETECTVERIFY = 0x00000014,
            DIF_INSTALLDEVICEFILES = 0x00000015,
            DIF_UNREMOVE = 0x00000016,
            DIF_SELECTBESTCOMPATDRV = 0x00000017,
            DIF_ALLOW_INSTALL = 0x00000018,
            DIF_REGISTERDEVICE = 0x00000019,
            DIF_NEWDEVICEWIZARD_PRESELECT = 0x0000001a,
            DIF_NEWDEVICEWIZARD_SELECT = 0x0000001b,
            DIF_NEWDEVICEWIZARD_PREANALYZE = 0x0000001c,
            DIF_NEWDEVICEWIZARD_POSTANALYZE = 0x0000001d,
            DIF_NEWDEVICEWIZARD_FINISHINSTALL = 0x0000001e,
            DIF_UNUSED1 = 0x0000001e,
            DIF_INSTALLINTERFACES = 0x00000020,
            DIF_DETECTCANCEL = 0x00000021,
            DIF_REGISTER_COINSTALLERS = 0x00000022,
            DIF_ADDPROPERTYPAGE_ADVANCED = 0x00000023,
            DIF_ADDPROPERTYPAGE_BASIC = 0x00000024,
            DIF_RESERVED1 = 0x00000025,
            DIF_TROUBLESHOOTER = 0x00000026,
            DIF_POWERMESSAGEWAKE = 0x00000027,
            DIF_ADDREMOTEPROPERTYPAGE_ADVANCED = 0x00000028,
            DIF_UPDATEDRIVER_UI = 0x00000029,
            DIF_FINISHINSTALL_ACTION = 0x0000002a,
        }

        [Flags]
        public enum DevPropType : uint
        {
            DEVPROP_TYPE_EMPTY = 0x00000000,  // nothing, no property data
            DEVPROP_TYPE_NULL = 0x00000001,  // null property data
            DEVPROP_TYPE_SBYTE = 0x00000002,
            DEVPROP_TYPE_BYTE = 0x00000003,
            DEVPROP_TYPE_INT16 = 0x00000004,
            DEVPROP_TYPE_UINT16 = 0x00000005,
            DEVPROP_TYPE_INT32 = 0x00000006,
            DEVPROP_TYPE_UINT32 = 0x00000007,
            DEVPROP_TYPE_INT64 = 0x00000008,
            DEVPROP_TYPE_UINT64 = 0x00000009,
            DEVPROP_TYPE_FLOAT = 0x0000000A,
            DEVPROP_TYPE_DOUBLE = 0x0000000B,
            DEVPROP_TYPE_DECIMAL = 0x0000000C,
            DEVPROP_TYPE_GUID = 0x0000000D,
            DEVPROP_TYPE_CURRENCY = 0x0000000E,  // 64 bit signed int currency value (CURRENCY)
            DEVPROP_TYPE_DATE = 0x0000000F,
            DEVPROP_TYPE_FILETIME = 0x00000010,
            DEVPROP_TYPE_BOOLEAN = 0x00000011,
            DEVPROP_TYPE_STRING = 0x00000012,
            DEVPROP_TYPE_STRING_LIST = (DEVPROP_TYPE_STRING | DEVPROP_TYPEMOD_LIST),
            DEVPROP_TYPE_SECURITY_DESCRIPTOR = 0x00000013,
            DEVPROP_TYPE_SECURITY_DESCRIPTOR_STRING = 0x00000014,
            DEVPROP_TYPE_DEVPROPKEY = 0x00000015,
            DEVPROP_TYPE_DEVPROPTYPE = 0x00000016,
            DEVPROP_TYPE_BINARY = (DEVPROP_TYPE_BYTE | DEVPROP_TYPEMOD_ARRAY),
            DEVPROP_TYPE_ERROR = 0x00000017,  // 32-bit Win32 system error code
            DEVPROP_TYPE_NTSTATUS = 0x00000018,  // 32-bit NTSTATUS code
            DEVPROP_TYPE_STRING_INDIRECT = 0x00000019,  // string resource (@[path\]<dllname>,-<strId>)

            // Property type modifiers, used to modify base DEVPROP_TYPE values and not valid as standalone
            // DEVPROPTYPE values.
            DEVPROP_TYPEMOD_ARRAY = 0x00001000,  // array of fixed-sized data elements
            DEVPROP_TYPEMOD_LIST = 0x00002000,  // list of variable-sized data elements
        }

        [Flags]
        public enum GetClassFlags : uint
        {
            DIGCF_DEFAULT = 0x00000001,
            DIGCF_PRESENT = 0x00000002,
            DIGCF_ALLCLASSES = 0x00000004,
            DIGCF_PROFILE = 0x00000008,
            DIGCF_DEVICEINTERFACE = 0x00000010,
        }

        [Flags]
        public enum InstallFlags : uint
        {
            DI_SHOWOEM = 0x00000001,
            DI_SHOWCOMPAT = 0x00000002,
            DI_SHOWCLASS = 0x00000004,
            DI_SHOWALL = 0x00000007,
            DI_NOVCP = 0x00000008,
            DI_DIDCOMPAT = 0x00000010,
            DI_DIDCLASS = 0x00000020,
            DI_AUTOASSIGNRES = 0x00000040,
            DI_NEEDRESTART = 0x00000080,
            DI_NEEDREBOOT = 0x00000100,
            DI_NOBROWSE = 0x00000200,
            DI_MULTMFGS = 0x00000400,
            DI_DISABLED = 0x00000800,
            DI_GENERALPAGE_ADDED = 0x00001000,
            DI_RESOURCEPAGE_ADDED = 0x00002000,
            DI_PROPERTIES_CHANGE = 0x00004000,
            DI_INF_IS_SORTED = 0x00008000,
            DI_ENUMSINGLEINF = 0x00010000,
            DI_DONOTCALLCONFIGMG = 0x00020000,
            DI_INSTALLDISABLED = 0x00040000,
            DI_COMPAT_FROM_CLASS = 0x00080000,
            DI_CLASSINSTALLPARAMS = 0x00100000,
            DI_NODI_DEFAULTACTION = 0x00200000,
            DI_QUIETINSTALL = 0x00800000,
            DI_NOFILECOPY = 0x01000000,
            DI_FORCECOPY = 0x02000000,
            DI_DRIVERPAGE_ADDED = 0x04000000,
            DI_USECI_SELECTSTRINGS = 0x08000000,
            DI_OVERRIDE_INFFLAGS = 0x10000000,
            DI_PROPS_NOCHANGEUSAGE = 0x20000000,
            DI_NOSELECTICONS = 0x40000000,
            DI_NOWRITE_IDS = 0x80000000,
        }

        [Flags]
        public enum InstallFlagsEx : uint
        {
            DI_FLAGSEX_RESERVED2 = 0x00000001,
            DI_FLAGSEX_RESERVED3 = 0x00000002,
            DI_FLAGSEX_CI_FAILED = 0x00000004,
            DI_FLAGSEX_FINISHINSTALL_ACTION = 0x00000008,
            DI_FLAGSEX_DIDINFOLIST = 0x00000010,
            DI_FLAGSEX_DIDCOMPATINFO = 0x00000020,
            DI_FLAGSEX_FILTERCLASSES = 0x00000040,
            DI_FLAGSEX_SETFAILEDINSTALL = 0x00000080,
            DI_FLAGSEX_DEVICECHANGE = 0x00000100,
            DI_FLAGSEX_ALWAYSWRITEIDS = 0x00000200,
            DI_FLAGSEX_PROPCHANGE_PENDING = 0x00000400,
            DI_FLAGSEX_ALLOWEXCLUDEDDRVS = 0x00000800,
            DI_FLAGSEX_NOUIONQUERYREMOVE = 0x00001000,
            DI_FLAGSEX_USECLASSFORCOMPAT = 0x00002000,
            DI_FLAGSEX_RESERVED4 = 0x00004000,
            DI_FLAGSEX_NO_DRVREG_MODIFY = 0x00008000,
            DI_FLAGSEX_IN_SYSTEM_SETUP = 0x00010000,
            DI_FLAGSEX_INET_DRIVER = 0x00020000,
            DI_FLAGSEX_APPENDDRIVERLIST = 0x00040000,
            DI_FLAGSEX_PREINSTALLBACKUP = 0x00080000,
            DI_FLAGSEX_BACKUPONREPLACE = 0x00100000,
            DI_FLAGSEX_DRIVERLIST_FROM_URL = 0x00200000,
            DI_FLAGSEX_RESERVED1 = 0x00400000,
            DI_FLAGSEX_EXCLUDE_OLD_INET_DRIVERS = 0x00800000,
            DI_FLAGSEX_POWERPAGE_ADDED = 0x01000000,
            DI_FLAGSEX_FILTERSIMILARDRIVERS = 0x02000000,
            DI_FLAGSEX_INSTALLEDDRIVER = 0x04000000,
            DI_FLAGSEX_NO_CLASSLIST_NODE_MERGE = 0x08000000,
            DI_FLAGSEX_ALTPLATFORM_DRVSEARCH = 0x10000000,
            DI_FLAGSEX_RESTART_DEVICE_ONLY = 0x20000000,
            DI_FLAGSEX_RECURSIVESEARCH = 0x40000000,
            DI_FLAGSEX_SEARCH_PUBLISHED_INFS = 0x80000000,
        }

        [Flags]
        public enum PropertyState : uint
        {
            DICS_ENABLE = 0x00000001,
            DICS_DISABLE = 0x00000002,
            DICS_PROPCHANGE = 0x00000003,
            DICS_START = 0x00000004,
            DICS_STOP = 0x00000005,
        }

        [Flags]
        public enum PropertyScope : uint
        {
            DICS_FLAG_GLOBAL = 0x00000001,
            DICS_FLAG_CONFIGSPECIFIC = 0x00000002,
            DICS_FLAG_CONFIGGENERAL = 0x00000004,
        }

        [Flags]
        public enum CMLocateFlags : uint
        {
            CM_LOCATE_DEVNODE_NORMAL = 0x00000000,
            CM_LOCATE_DEVNODE_PHANTOM = 0x00000001,
            CM_LOCATE_DEVNODE_CANCELREMOVE = 0x00000002,
            CM_LOCATE_DEVNODE_NOVALIDATION = 0x00000004,
            CM_LOCATE_DeVNODE_BITS = 0x00000007,
        }

        [Flags]
        public enum CMReenumerateFlags : uint
        {
            CM_REENUMERATE_NORMAL = 0x00000000,
            CM_REENUMERATE_SYNCHRONOUS = 0x00000001,
            CM_REENUMERATE_RETRY_INSTALLATION = 0x00000002,
            CM_REENUMERATE_ASYNCHRONOUS = 0x00000004,
            CM_REENUMERATE_BITS = 0x00000007,
        }
    }

    internal class NativeMethods
    {
        [DllImport("CfgMgr32.dll", CharSet = CharSet.Unicode)]
        public static extern UInt32 CM_Locate_DevNodeW(
            out IntPtr pdnDevInst,
            [MarshalAs(UnmanagedType.LPWStr)] string pDeviceId,
            NativeHelpers.CMLocateFlags ulFlags);

        [DllImport("CfgMgr32.dll", CharSet = CharSet.Unicode)]
        public static extern UInt32 CM_Reenumerate_DevNode(
            IntPtr dnDevInst,
            NativeHelpers.CMReenumerateFlags ulFlags);

        [DllImport("SetupAPI.dll", SetLastError = true)]
        public static extern bool SetupDiCallClassInstaller(
            NativeHelpers.DifCodes InstallFunction,
            SafeDeviceInfoSet DeviceInfoSet,
            NativeHelpers.SP_DEVINFO_DATA DeviceInfoData);

        [DllImport("SetupAPI.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool SetupDiClassNameFromGuidExW(
            Guid ClassGuid,
            StringBuilder ClassName,
            UInt32 ClassNameSize,
            out UInt32 RequiredSize,
            [MarshalAs(UnmanagedType.LPWStr)] string MachineName,
            IntPtr Reserved);

        [DllImport("SetupAPI.dll", SetLastError = true)]
        public static extern bool SetupDiDestroyDeviceInfoList(
            IntPtr DeviceInfoSet);

        [DllImport("SetupAPI.dll", SetLastError = true)]
        public static extern bool SetupDiEnumDeviceInfo(
            SafeDeviceInfoSet DeviceInfoSet,
            UInt32 MemberIndex,
            NativeHelpers.SP_DEVINFO_DATA DeviceInfoData);

        [DllImport("SetupAPI.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool SetupDiGetClassDescriptionExW(
            Guid ClassGuid,
            StringBuilder ClassDescription,
            UInt32 ClassDescriptionSize,
            out UInt32 RequiredSize,
            [MarshalAs(UnmanagedType.LPWStr)] string MachineName,
            IntPtr Reserved);

        [DllImport("SetupAPI.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern SafeDeviceInfoSet SetupDiGetClassDevsExW(
            Guid ClassGuid,
            [MarshalAs(UnmanagedType.LPWStr)] string Enumerator,
            IntPtr hwndParent,
            NativeHelpers.GetClassFlags Flags,
            SafeDeviceInfoSet DeviceInfoSet,
            [MarshalAs(UnmanagedType.LPWStr)] string MachineName,
            IntPtr Reserved);

        [DllImport("SetupAPI.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool SetupDiGetDeviceInstallParams(
            SafeDeviceInfoSet DeviceInfoSet,
            NativeHelpers.SP_DEVINFO_DATA DeviceInfoData,
            ref NativeHelpers.SP_DEVINSTALL_PARAMS DeviceInstallParams);

        [DllImport("SetupAPI.dll", SetLastError = true)]
        public static extern bool SetupDiGetDevicePropertyKeys(
            SafeDeviceInfoSet DeviceInfoSet,
            NativeHelpers.SP_DEVINFO_DATA DeviceInfoData,
            SafeMemoryBuffer PropertyKeyArray,
            UInt32 PropertyKeyCount,
            out UInt32 RequiredPropertyKeyCount,
            UInt32 Flags);

        [DllImport("SetupAPI.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool SetupDiGetDevicePropertyW(
            SafeDeviceInfoSet DeviceInfoSet,
            NativeHelpers.SP_DEVINFO_DATA DeviceInfoData,
            NativeHelpers.DEVPROPKEY PropertyKey,
            out NativeHelpers.DevPropType PropertyType,
            SafeMemoryBuffer PropertyBuffer,
            UInt32 PropertyBufferSize,
            out UInt32 RequiredSize,
            UInt32 Flags);

        [DllImport("SetupAPI.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool SetupDiSetClassInstallParamsW(
            SafeDeviceInfoSet DeviceInfoSet,
            NativeHelpers.SP_DEVINFO_DATA DeviceInfoData,
            SafeMemoryBuffer ClassInstallParams,
            UInt32 ClassInstallParamsSize);
    }

    internal class SafeDeviceInfoSet : SafeHandleMinusOneIsInvalid
    {
        public SafeDeviceInfoSet() : base(true) { }

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
        protected override bool ReleaseHandle()
        {
            return NativeMethods.SetupDiDestroyDeviceInfoList(handle);
        }
    }

    internal class SafeMemoryBuffer : SafeHandleMinusOneIsInvalid
    {
        public SafeMemoryBuffer() : base(true) { }
        public SafeMemoryBuffer(int cb) : base(true)
        {
            base.SetHandle(Marshal.AllocHGlobal(cb));
        }
        public SafeMemoryBuffer(IntPtr ptr) : base(true)
        {
            base.SetHandle(ptr);
        }

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
        protected override bool ReleaseHandle()
        {
            if (handle != IntPtr.Zero)
                Marshal.FreeHGlobal(handle);
            return true;
        }
    }

    internal class Win32Exception : System.ComponentModel.Win32Exception
    {
        private string _msg;

        public Win32Exception(string message) : this(Marshal.GetLastWin32Error(), message) { }
        public Win32Exception(int errorCode, string message) : base(errorCode)
        {
            _msg = String.Format("{0} ({1}, Win32ErrorCode {2} - 0x{2:X8})", message, base.Message, errorCode);
        }

        public override string Message { get { return _msg; } }
        public static explicit operator Win32Exception(string message) { return new Win32Exception(message); }
    }

    public enum DeviceErrorCode : uint
    {
        None = 0x00000000,
        NotConfigured = 0x00000001,
        DevLoaderFailer = 0x00000002,
        OutOfMemory = 0x00000003,
        EntryIsWrongType = 0x00000004,
        LackedArbitrator = 0x00000005,
        BootConfigConflict = 0x00000006,
        FailedFilter = 0x00000007,
        DevLoaderNotFound = 0x00000008,
        InvalidData = 0x00000009,
        FailedStart = 0x0000000A,
        Liar = 0x0000000B,
        NormalConflict = 0x0000000C,
        NotVerified = 0x0000000D,
        NeedRestart = 0x0000000E,
        Reenumeration = 0x0000000F,
        PartialLogConf = 0x00000010,
        UnknownResource = 0x00000011,
        Reinstall = 0x00000012,
        Registry = 0x00000013,
        Vxdldr = 0x00000014,
        WillBeRemoved = 0x00000015,
        Disabled = 0x00000016,
        DevloaderNotReady = 0x00000017,
        DeviceNotThere = 0x00000018,
        Moved = 0x00000019,
        TooEarly = 0x0000001A,
        NoValidLogConf = 0x0000001B,
        FailedInstall = 0x0000001C,
        HardwareDisabled = 0x0000001D,
        CantShareIRQ = 0x0000001E,
        FailedAdd = 0x0000001F,
        DisabledService = 0x00000020,
        TranslationFailed = 0x00000021,
        NoSoftconfig = 0x00000022,
        BiosTable = 0x00000023,
        IRQTranslationFailed = 0x00000024,
        FailedDriverEntry = 0x00000025,
        DriverFailedPriorUnload = 0x00000026,
        DriverFailedLoad = 0x00000027,
        DriverServiceKeyInvalid = 0x00000028,
        LegacyServiceNoDevices = 0x00000029,
        DuplicateDevice = 0x0000002A,
        FailedPostStart = 0x0000002B,
        Halted = 0x0000002C,
        Phantom = 0x0000002D,
        SystemShutdown = 0x0000002E,
        HeldForEject = 0x0000002F,
        DriverBlocked = 0x00000030,
        RegistryTooLarge = 0x00000031,
        SetPropertiesFailed = 0x00000032,
        WaitingOnDependency = 0x00000033,
        UnsignedDriver = 0x00000034,
        UsedByDebugger = 0x00000035,
        DeviceReset = 0x00000036,
        ConsoleLocked = 0x00000037,
        NeedClassConfig = 0x00000038,
    }

    [Flags]
    public enum DeviceStatus : uint
    {
        Unknown = 0x00000000,
        RootEnumerated = 0x00000001,
        DriverLoaded = 0x00000002,
        EnumLoaded = 0x00000004,
        Started = 0x00000008,
        Manual = 0x00000010,
        NeedToEnum = 0x00000020,
        NotFirstTime = 0x00000040,
        HardwareEnum = 0x00000080,
        Liar = 0x00000100,
        HasMark = 0x00000200,
        HasProblem = 0x00000400,
        Filtered = 0x00000800,
        Moved = 0x00001000,
        Disableable = 0x00002000,
        Removable = 0x00004000,
        PrivateProblem = 0x00008000,
        MfParent = 0x00010000,
        MfChild = 0x00020000,
        WillBeRemoved = 0x00040000,
        NotFirstTimee = 0x00080000,
        StopFreeRes = 0x00100000,
        RebalCandidate = 0x00200000,
        BadPartial = 0x00400000,
        NTEnumerator = 0x00800000,
        NTDriver = 0x01000000,
        NeedsLocking = 0x02000000,
        ApmWakeup = 0x04000000,
        ApmEnumerator = 0x08000000,
        ApmDriver = 0x10000000,
        SilentInstall = 0x20000000,
        NoShowInDm = 0x40000000,
        BootLogProb = 0x80000000,
        NeedRestart = Liar,
        DriverBlocked = NotFirstTime,
        LegacyDriver = Moved,
        ChildWithInvalidId = HasMark,
        DeviceDisconnected = NeedsLocking,
        QueryRemovePending = MfParent,
        QueryRemoveActive = MfChild,
    }

    public class Device : IDisposable
    {
        private static int ERROR_NO_MORE_ITEMS = 0x00000103;
        private static int ERROR_INSUFFICIENT_BUFFER = 0x0000007A;
        private static int ERROR_NOT_FOUND = 0x00000490;

        public string ClassDescription;
        public Guid ClassGuid;
        public string ClassName;
        public List<string> CompatibleIds;
        public Guid ContainerId;
        public string Description;
        public string Enumerator;
        public List<string> HardwareIds;
        public string InstanceId;  // Unique identifier of the device
        public string Manufacturer;
        public string Name;
        public string PDOName;
        public bool Present;
        public DeviceErrorCode ProblemCode;
        public DeviceStatus Status;

        private SafeDeviceInfoSet devInfoSet;
        private NativeHelpers.SP_DEVINFO_DATA devInfoData;

        internal Device(SafeDeviceInfoSet devInfoSet, NativeHelpers.SP_DEVINFO_DATA devInfoData)
        {
            this.devInfoSet = devInfoSet;
            this.devInfoData = devInfoData;

            ClassGuid = (Guid)GetProperty("DEVPKEY_Device_ClassGuid", defaultValue: Guid.Empty);
            ClassName = ClassNameFromGuidEx(ClassGuid, null);
            ClassDescription = GetClassDescriptionEx(ClassGuid, null);
            ContainerId = (Guid)GetProperty("DEVPKEY_Device_ContainerId", defaultValue: Guid.Empty);
            CompatibleIds = (List<string>)GetProperty("DEVPKEY_Device_CompatibleIds", defaultValue: null);
            Description = (string)GetProperty("DEVPKEY_Device_DeviceDesc", defaultValue: null);
            Enumerator = (string)GetProperty("DEVPKEY_Device_EnumeratorName", defaultValue: null);
            HardwareIds = (List<string>)GetProperty("DEVPKEY_Device_HardwareIds", defaultValue: null);
            InstanceId = (string)GetProperty("DEVPKEY_Device_InstanceId");
            Manufacturer = (string)GetProperty("DEVPKEY_Device_Manufacturer", defaultValue: null);
            Name = (string)GetProperty("DEVPKEY_NAME", defaultValue: null);
            PDOName = (string)GetProperty("DEVPKEY_Device_PDOName", defaultValue: null);
            Present = (bool)GetProperty("DEVPKEY_Device_IsPresent");
            UpdateStatus();
        }

        /// <summary>
        /// Disables a device if it is enabled. Throws InvalidOperation if the device cannot be disabled.
        /// </summary>
        /// <returns>Whether a reboot is required.</returns>
        public bool Disable()
        {
            return ChangePropertyState(NativeHelpers.PropertyState.DICS_DISABLE);
        }

        public object GetProperty(string property)
        {
            return GetDeviceProperty(devInfoSet, devInfoData, NativeHelpers.DEVPROPKEY.FromString(property));
        }

        public object GetProperty(string property, object defaultValue = null)
        {
            try
            {
                return GetProperty(property);
            }
            catch (ArgumentException)
            {
                return defaultValue;
            }
        }

        public Dictionary<string, object> GetProperties()
        {
            NativeHelpers.DEVPROPKEY[] keys = GetDevicePropertyKeys(devInfoSet, devInfoData);
            Dictionary<string, object> properties = new Dictionary<string, object>();
            foreach (NativeHelpers.DEVPROPKEY key in keys)
                properties[key.ToString()] = GetDeviceProperty(devInfoSet, devInfoData, key);

            return properties;
        }

        /// <summary>
        /// Enables a device if it is disabled.
        /// </summary>
        /// <returns>Whether a reboot is required.</returns>
        public bool Enable()
        {
            return ChangePropertyState(NativeHelpers.PropertyState.DICS_ENABLE);
        }

        /// <summary>
        /// Removes a device and rescan for hardware changes if rescan: true.
        /// </summary>
        /// <param name="rescan">Rescan for harwdware changed if true (default: true).</param>
        /// <returns>Whether a reboot is required.</returns>
        public bool Remove(bool rescan = true)
        {
            CallClassInstaller(NativeHelpers.DifCodes.DIF_REMOVE, devInfoSet, devInfoData);
            NativeHelpers.SP_DEVINSTALL_PARAMS installParams = GetDeviceInstallParams(devInfoSet, devInfoData);
            Dispose();

            if (rescan)
                RescanHardwareChanges();

            return installParams.Flags.HasFlag(NativeHelpers.InstallFlags.DI_NEEDREBOOT) ||
                installParams.Flags.HasFlag(NativeHelpers.InstallFlags.DI_NEEDRESTART);
        }

        /// <summary>
        /// Starts the device if it is stopped.
        /// </summary>
        /// <returns>Whether a reboot is required.</returns>
        public bool Start()
        {
            return ChangePropertyState(NativeHelpers.PropertyState.DICS_START);
        }

        /// <summary>
        /// Stops the device if it is started.
        /// </summary>
        /// <returns>Whether a reboot is required.</returns>
        public bool Stop()
        {
            return ChangePropertyState(NativeHelpers.PropertyState.DICS_STOP);
        }

        private bool ChangePropertyState(NativeHelpers.PropertyState state)
        {
            UpdateStatus();

            if (state == NativeHelpers.PropertyState.DICS_DISABLE || state == NativeHelpers.PropertyState.DICS_ENABLE)
            {
                if (!Status.HasFlag(DeviceStatus.Disableable))
                {
                    string action = state.ToString().Substring(4).ToLowerInvariant();
                    string msg = String.Format("Cannot {0} device '{1}'", action, InstanceId);
                    throw new InvalidOperationException(msg);
                }
                else if ((state == NativeHelpers.PropertyState.DICS_DISABLE) == (ProblemCode == DeviceErrorCode.Disabled))
                    return false;
            }
            else if (state == NativeHelpers.PropertyState.DICS_START && Status.HasFlag(DeviceStatus.Started))
                return false;
            else if (state == NativeHelpers.PropertyState.DICS_STOP && !Status.HasFlag(DeviceStatus.Started))
                return false;

            NativeHelpers.SP_PROPCHANGE_PARAMS changeParams = new NativeHelpers.SP_PROPCHANGE_PARAMS()
            {
                ClassInstallHeader = new NativeHelpers.SP_CLASSINSTALL_HEADER
                {
                    InstallFunction = NativeHelpers.DifCodes.DIF_PROPERTYCHANGE,
                },
                StateChange = state,
                HwProfile = 0,
            };

            // I'm unsure why we need to only do this for ENABLE but it's in devcon so we copy that here.
            // https://github.com/microsoft/Windows-driver-samples/blob/master/setup/devcon/cmds.cpp
            if (state == NativeHelpers.PropertyState.DICS_ENABLE)
            {
                changeParams.Scope = NativeHelpers.PropertyScope.DICS_FLAG_GLOBAL;
                SetClassInstallParams(devInfoSet, devInfoData, changeParams);
                CallClassInstaller(changeParams.ClassInstallHeader.InstallFunction, devInfoSet, devInfoData);
            }

            changeParams.Scope = NativeHelpers.PropertyScope.DICS_FLAG_CONFIGSPECIFIC;
            SetClassInstallParams(devInfoSet, devInfoData, changeParams);
            CallClassInstaller(changeParams.ClassInstallHeader.InstallFunction, devInfoSet, devInfoData);

            NativeHelpers.SP_DEVINSTALL_PARAMS installParams = GetDeviceInstallParams(devInfoSet, devInfoData);
            UpdateStatus();

            return installParams.Flags.HasFlag(NativeHelpers.InstallFlags.DI_NEEDREBOOT) ||
                installParams.Flags.HasFlag(NativeHelpers.InstallFlags.DI_NEEDRESTART);
        }

        private void UpdateStatus()
        {
            ProblemCode = (DeviceErrorCode)(UInt32)GetProperty("DEVPKEY_Device_ProblemCode", defaultValue: (UInt32)0);
            Status = (DeviceStatus)(UInt32)GetProperty("DEVPKEY_Device_DevNodeStatus", defaultValue: (UInt32)0);
        }

        public void Dispose()
        {
            this.devInfoSet.Dispose();
            GC.SuppressFinalize(this);
        }
        ~Device() { Dispose(); }

        /// <summary>
        /// Opens a particular device by the device's InstanceId. Throws ArgumentException if the device was not found.
        /// </summary>
        /// <param name="instanceId">The device's InstanceId (Device instance path in the GUI).</param>
        /// <returns>The opened device.</returns>
        public static Device OpenDevice(string instanceId)
        {
            Device device = null;
            NativeHelpers.GetClassFlags getFlags = NativeHelpers.GetClassFlags.DIGCF_ALLCLASSES |
                NativeHelpers.GetClassFlags.DIGCF_DEVICEINTERFACE;

            foreach (Device d in EnumerateDevices(Guid.Empty, instanceId, getFlags, null))
            {
                device = d;
                break;
            }

            if (device == null)
                throw new ArgumentException("Failed to find device with the id '{0}'", instanceId);

            return device;
        }

        /// <summary>
        /// Enumerate all the devices on the Windows host.
        /// </summary>
        /// <returns>The devices that were found.</returns>
        public static IEnumerable<Device> EnumerateDevices()
        {
            return EnumerateDevices(null);
        }

        /// <summary>
        /// Enumerate all the devices based on the root enumerator specified.
        /// </summary>
        /// <param name="enumerator">The root enumerate to filter the devices by like ACPI, PCI, etc.</param>
        /// <returns>The devices that were found with the root enumerator specified.</returns>
        public static IEnumerable<Device> EnumerateDevices(string enumerator)
        {
            return EnumerateDevices(Guid.Empty, enumerator, NativeHelpers.GetClassFlags.DIGCF_ALLCLASSES, null);
        }

        private static IEnumerable<Device> EnumerateDevices(Guid classGuid, string enumerator,
            NativeHelpers.GetClassFlags flags, string hostname)
        {
            SafeDeviceInfoSet devInfoSet = GetClassDevsEx(classGuid, enumerator, flags, hostname);
            UInt32 idx = 0;
            while (true)
            {
                NativeHelpers.SP_DEVINFO_DATA devInfoData = new NativeHelpers.SP_DEVINFO_DATA();
                if (!NativeMethods.SetupDiEnumDeviceInfo(devInfoSet, idx, devInfoData))
                {
                    int err = Marshal.GetLastWin32Error();
                    if (err == ERROR_NO_MORE_ITEMS)
                        break;
                    throw new Win32Exception(err, "SetupDiEnumDeviceInfo() failed");
                }

                yield return new Device(devInfoSet, devInfoData);
                idx++;
            }
        }

        private static void CallClassInstaller(NativeHelpers.DifCodes installFunction, SafeDeviceInfoSet devInfoSet,
            NativeHelpers.SP_DEVINFO_DATA devInfoData)
        {
            if (!NativeMethods.SetupDiCallClassInstaller(installFunction, devInfoSet, devInfoData))
                throw new Win32Exception("Failed to call class installer for device");
        }

        private static string ClassNameFromGuidEx(Guid classGuid, string hostname)
        {
            if (classGuid == Guid.Empty)
                return "Unknown";

            StringBuilder className = new StringBuilder(0);
            UInt32 requiredSize = 0;
            if (!NativeMethods.SetupDiClassNameFromGuidExW(classGuid, className, requiredSize, out requiredSize,
                hostname, IntPtr.Zero))
            {
                int err = Marshal.GetLastWin32Error();
                if (err != ERROR_INSUFFICIENT_BUFFER)
                {
                    string msg = String.Format("Failed to get class name buffer size for the class guid {0}",
                        classGuid.ToString());
                    throw new Win32Exception(err, msg);
                }
            }

            className.EnsureCapacity((int)requiredSize);
            if (!NativeMethods.SetupDiClassNameFromGuidExW(classGuid, className, requiredSize, out requiredSize,
                hostname, IntPtr.Zero))
            {
                string msg = String.Format("Failed to get the class name for the class guid {0}",
                    classGuid.ToString());
                throw new Win32Exception(msg);
            }

            return className.ToString();
        }

        private static SafeDeviceInfoSet GetClassDevsEx(Guid classGuid, string enumerator,
            NativeHelpers.GetClassFlags flags, string hostname)
        {
            enumerator = String.IsNullOrEmpty(enumerator) ? null : enumerator;
            SafeDeviceInfoSet devInfoSet = NativeMethods.SetupDiGetClassDevsExW(classGuid, enumerator, IntPtr.Zero,
                flags, new SafeDeviceInfoSet(), hostname, IntPtr.Zero);

            if (devInfoSet.IsInvalid)
                throw new Win32Exception("SetupDiGetClassDevsW() failed");

            return devInfoSet;
        }

        private static string GetClassDescriptionEx(Guid classGuid, string hostname)
        {
            if (classGuid == Guid.Empty)
                return "Other devices";

            StringBuilder classDescription = new StringBuilder(0);
            UInt32 requiredSize = 0;
            if (!NativeMethods.SetupDiGetClassDescriptionExW(classGuid, classDescription, requiredSize,
                out requiredSize, hostname, IntPtr.Zero))
            {
                int err = Marshal.GetLastWin32Error();
                if (err != ERROR_INSUFFICIENT_BUFFER)
                {
                    string msg = String.Format("Failed to get class description buffer size for the class guid {0}",
                        classGuid.ToString());
                    throw new Win32Exception(err, msg);
                }
            }

            classDescription.EnsureCapacity((int)requiredSize);
            if (!NativeMethods.SetupDiGetClassDescriptionExW(classGuid, classDescription, requiredSize,
                out requiredSize, hostname, IntPtr.Zero))
            {
                string msg = String.Format("Failed to get the class description for the class guid {0}",
                    classGuid.ToString());
                throw new Win32Exception(msg);
            }

            return classDescription.ToString();
        }

        private static NativeHelpers.SP_DEVINSTALL_PARAMS GetDeviceInstallParams(SafeDeviceInfoSet devInfoSet,
            NativeHelpers.SP_DEVINFO_DATA devInfoData)
        {
            NativeHelpers.SP_DEVINSTALL_PARAMS installParams = new NativeHelpers.SP_DEVINSTALL_PARAMS();
            installParams.cbSize = (UInt32)Marshal.SizeOf(typeof(NativeHelpers.SP_DEVINSTALL_PARAMS));
            if (!NativeMethods.SetupDiGetDeviceInstallParams(devInfoSet, devInfoData, ref installParams))
                throw new Win32Exception("Failed to get device install params");

            return installParams;
        }

        private static NativeHelpers.DEVPROPKEY[] GetDevicePropertyKeys(SafeDeviceInfoSet devInfoSet,
            NativeHelpers.SP_DEVINFO_DATA devInfoData)
        {
            UInt32 requiredCount = 0;
            if (!NativeMethods.SetupDiGetDevicePropertyKeys(devInfoSet, devInfoData,
                new SafeMemoryBuffer(IntPtr.Zero), 0, out requiredCount, 0))
            {
                int err = Marshal.GetLastWin32Error();
                if (err != ERROR_INSUFFICIENT_BUFFER)
                    throw new Win32Exception(err, "SetupDiGetDevicePropertyKeys() failed to get buffer length");
            }

            NativeHelpers.DEVPROPKEY[] propertyKeys = new NativeHelpers.DEVPROPKEY[(int)requiredCount];
            int bufferSize = (Int32)requiredCount * Marshal.SizeOf(typeof(NativeHelpers.DEVPROPKEY));
            using (SafeMemoryBuffer buffer = new SafeMemoryBuffer(bufferSize))
            {
                if (!NativeMethods.SetupDiGetDevicePropertyKeys(devInfoSet, devInfoData, buffer, requiredCount,
                    out requiredCount, 0))
                {
                    throw new Win32Exception("SetuPDiGetDevicePropertyKeys() failed to get prop keys");
                }
                PtrToStructureArray(buffer.DangerousGetHandle(), propertyKeys);
            }

            return propertyKeys;
        }

        private static object GetDeviceProperty(SafeDeviceInfoSet devInfoSet,
            NativeHelpers.SP_DEVINFO_DATA devInfoData, NativeHelpers.DEVPROPKEY propertyKey)
        {
            NativeHelpers.DevPropType propertyType = 0;
            UInt32 requiredSize = 0;
            if (!NativeMethods.SetupDiGetDevicePropertyW(devInfoSet, devInfoData, propertyKey, out propertyType,
                new SafeMemoryBuffer(IntPtr.Zero), 0, out requiredSize, 0))
            {
                int err = Marshal.GetLastWin32Error();
                if (err == ERROR_NOT_FOUND)
                {
                    throw new ArgumentException(String.Format("The property {0} was not found on the device",
                        propertyKey.ToString()));
                }
                else if (err != ERROR_INSUFFICIENT_BUFFER)
                    throw new Win32Exception(err, "SetupDiGetDevicePropertyW() failed to get output buffer size");
            }

            if (propertyType == NativeHelpers.DevPropType.DEVPROP_TYPE_EMPTY)
                throw new KeyNotFoundException(String.Format("The property {0} was not found on the device",
                    propertyKey.ToString()));
            else if (propertyType == NativeHelpers.DevPropType.DEVPROP_TYPE_NULL)
                return null;

            byte[] bufferBytes = new byte[(int)requiredSize];
            using (SafeMemoryBuffer buffer = new SafeMemoryBuffer((int)requiredSize))
            {
                if (!NativeMethods.SetupDiGetDevicePropertyW(devInfoSet, devInfoData, propertyKey,
                    out propertyType, buffer, requiredSize, out requiredSize, 0))
                {
                    throw new Win32Exception("SetupDiGetDevicePropertyW() failed");
                }

                Marshal.Copy(buffer.DangerousGetHandle(), bufferBytes, 0, bufferBytes.Length);
            }

            return ParsePropertyValue(bufferBytes, propertyType);
        }

        private void RescanHardwareChanges()
        {
            IntPtr devRoot = IntPtr.Zero;
            UInt32 err = NativeMethods.CM_Locate_DevNodeW(out devRoot, null, NativeHelpers.CMLocateFlags.CM_LOCATE_DEVNODE_NORMAL);
            if (err != 0)
                throw new Exception(String.Format("Failed to find dev node for rescanning: {0}", err));

            err = NativeMethods.CM_Reenumerate_DevNode(devRoot, NativeHelpers.CMReenumerateFlags.CM_REENUMERATE_NORMAL);
            if (err != 0)
                throw new Exception(String.Format("Failed to reenumerate hardware device changes: {0}", err));
        }

        private void SetClassInstallParams(SafeDeviceInfoSet devInfoSet, NativeHelpers.SP_DEVINFO_DATA devInfoData,
            object structure)
        {
            int bufferSize = Marshal.SizeOf(structure);
            using (SafeMemoryBuffer buffer = new SafeMemoryBuffer(bufferSize))
            {
                Marshal.StructureToPtr(structure, buffer.DangerousGetHandle(), false);

                if (!NativeMethods.SetupDiSetClassInstallParamsW(devInfoSet, devInfoData, buffer, (UInt32)bufferSize))
                    throw new Win32Exception("Failed to set class install params for device");
            }
        }

        private static object ParsePropertyValue(byte[] bytes, NativeHelpers.DevPropType type)
        {
            if (type == NativeHelpers.DevPropType.DEVPROP_TYPE_SBYTE)
                return (sbyte)bytes[0];
            else if (type == NativeHelpers.DevPropType.DEVPROP_TYPE_BYTE)
                return bytes[0];
            else if (type == NativeHelpers.DevPropType.DEVPROP_TYPE_INT16)
                return BitConverter.ToInt16(bytes, 0);
            else if (type == NativeHelpers.DevPropType.DEVPROP_TYPE_UINT16)
                return BitConverter.ToUInt16(bytes, 0);
            else if (type == NativeHelpers.DevPropType.DEVPROP_TYPE_INT32 ||
                type == NativeHelpers.DevPropType.DEVPROP_TYPE_ERROR ||
                type == NativeHelpers.DevPropType.DEVPROP_TYPE_NTSTATUS)
            {
                return BitConverter.ToInt32(bytes, 0);
            }
            else if (type == NativeHelpers.DevPropType.DEVPROP_TYPE_UINT32)
                return BitConverter.ToUInt32(bytes, 0);
            else if (type == NativeHelpers.DevPropType.DEVPROP_TYPE_INT64 ||
                type == NativeHelpers.DevPropType.DEVPROP_TYPE_CURRENCY)
            {
                return BitConverter.ToInt64(bytes, 0);
            }
            else if (type == NativeHelpers.DevPropType.DEVPROP_TYPE_UINT64)
                return BitConverter.ToUInt64(bytes, 0);
            else if (type == NativeHelpers.DevPropType.DEVPROP_TYPE_FLOAT)
                return BitConverter.ToSingle(bytes, 0);
            else if (type == NativeHelpers.DevPropType.DEVPROP_TYPE_DOUBLE)
                return BitConverter.ToDouble(bytes, 0);
            else if (type == NativeHelpers.DevPropType.DEVPROP_TYPE_DECIMAL)
            {
                int[] bits = new int[4]
                {
                    bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24),
                    bytes[4] | (bytes[5] << 8) | (bytes[6] << 16) | (bytes[7] << 24),
                    bytes[8] | (bytes[9] << 8) | (bytes[10] << 16) | (bytes[11] << 24),
                    bytes[12] | (bytes[13] << 8) | (bytes[14] << 16) | (bytes[15] << 24),
                };
                return new Decimal(bits);
            }
            else if (type == NativeHelpers.DevPropType.DEVPROP_TYPE_GUID)
                return new Guid(bytes);
            else if (type == NativeHelpers.DevPropType.DEVPROP_TYPE_DATE)
            {
                Double doubleVal = BitConverter.ToDouble(bytes, 0);
                return DateTime.FromOADate(doubleVal);
            }
            else if (type == NativeHelpers.DevPropType.DEVPROP_TYPE_FILETIME)
            {
                Int64 fileTime = BitConverter.ToInt64(bytes, 0);
                return DateTime.FromFileTime(fileTime);
            }
            else if (type == NativeHelpers.DevPropType.DEVPROP_TYPE_BOOLEAN)
                return BitConverter.ToBoolean(bytes, 0);
            else if (type == NativeHelpers.DevPropType.DEVPROP_TYPE_STRING ||
                type == NativeHelpers.DevPropType.DEVPROP_TYPE_SECURITY_DESCRIPTOR_STRING ||
                type == NativeHelpers.DevPropType.DEVPROP_TYPE_STRING_INDIRECT)
            {
                string stringVal = Encoding.Unicode.GetString(bytes);
                return stringVal.Substring(0, stringVal.Length - 1);
            }
            else if (type == NativeHelpers.DevPropType.DEVPROP_TYPE_STRING_LIST)
            {
                string stringVal = Encoding.Unicode.GetString(bytes);
                return stringVal.Substring(0, stringVal.Length - 2).Split('\0').ToList<string>();
            }
            else if (type == NativeHelpers.DevPropType.DEVPROP_TYPE_SECURITY_DESCRIPTOR)
                return new RawSecurityDescriptor(bytes, 0);
            else if (type == NativeHelpers.DevPropType.DEVPROP_TYPE_DEVPROPKEY)
            {
                using (SafeMemoryBuffer buffer = new SafeMemoryBuffer(bytes.Length))
                {
                    Marshal.Copy(bytes, 0, buffer.DangerousGetHandle(), bytes.Length);
                    NativeHelpers.DEVPROPKEY propKey = (NativeHelpers.DEVPROPKEY)Marshal.PtrToStructure(
                        buffer.DangerousGetHandle(), typeof(NativeHelpers.DEVPROPKEY));
                    return propKey.ToString();
                }
            }
            else if (type == NativeHelpers.DevPropType.DEVPROP_TYPE_DEVPROPTYPE)
            {
                UInt32 uintVal = BitConverter.ToUInt32(bytes, 0);
                return ((NativeHelpers.DevPropType)uintVal).ToString();
            }
            else
                return bytes;
        }

        private static void PtrToStructureArray<T>(IntPtr ptr, T[] array)
        {
            IntPtr currentPtr = ptr;
            for (int i = 0; i < array.Length; i++)
            {
                array[i] = (T)Marshal.PtrToStructure(currentPtr, typeof(T));
                currentPtr = IntPtr.Add(currentPtr, Marshal.SizeOf(typeof(T)));
            }
        }
    }
}
'@

([Object[]][SetupAPI.Device]::EnumerateDevices("ACPI")) | Where-Object {
    $_.Name -eq "HID Button over Interrupt Driver" -and $_.ProblemCode -eq [SetupAPI.DeviceErrorCode]::FailedAdd
} | ForEach-Object -Process {
    Write-Host "Removing device $($_.Name) - $($_.InstanceId)"
    $_.Remove($true)
}
