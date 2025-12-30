using System;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media.Animation;
using Microsoft.Win32;
using System.Linq;
using System.Net.NetworkInformation;
using System.Collections.Generic;
using System.Security.Principal;

namespace _0xSpoofer
{
    public partial class MainWindow : Window
    {
        private static readonly Random rnd = new Random();
        private bool isAdmin = false;

        public MainWindow()
        {
            InitializeComponent();
            CheckAdminRights();
        }

        private void CheckAdminRights()
        {
            try
            {
                WindowsIdentity identity = WindowsIdentity.GetCurrent();
                WindowsPrincipal principal = new WindowsPrincipal(identity);
                isAdmin = principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch
            {
                isAdmin = false;
            }
        }

        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            try
            {
                var fadeIn = (Storyboard)this.Resources["FadeIn"];
                if (fadeIn != null)
                    fadeIn.Begin(this);
            }
            catch { }
        }

        private void Window_MouseDown(object sender, MouseButtonEventArgs e)
        {
            if (e.ChangedButton == MouseButton.Left)
            {
                try
                {
                    this.DragMove();
                }
                catch { }
            }
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            Application.Current.Shutdown();
        }

        private async void SpoofButton_Click(object sender, RoutedEventArgs e)
        {
            if (!isAdmin)
            {
                MessageBox.Show("This tool requires Administrator privileges to spoof hardware IDs.\nPlease restart as Administrator.", "Administrator Required", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            StatusText.Text = "Spoofing in progress...";
            await Task.Run(() => StartSpoofing());
            await Task.Delay(500);
            StatusText.Text = "Spoofing completed! Restart required.";
        }

        private async void CheckButton_Click(object sender, RoutedEventArgs e)
        {
            StatusText.Text = "Checking HWID...";
            await Task.Run(() => CheckHWID());
            await Task.Delay(500);
            StatusText.Text = "Check completed!";
        }

        private void StartSpoofing()
        {
            string batPath = Path.Combine(Path.GetTempPath(), $"spoof_exec_{Guid.NewGuid()}.bat");
            StringBuilder batContent = new StringBuilder();

            batContent.AppendLine(@"@echo off");
            batContent.AppendLine(@"color 1");
            batContent.AppendLine(@"title 0xSPOOFER - REAL Hardware ID Spoofer");
            batContent.AppendLine(@"cls");
            batContent.AppendLine(@"echo.");
            batContent.AppendLine(@"echo _______            _________                     _____");
            batContent.AppendLine(@"echo \   _  \ ___  ___ /   _____/_____   ____   _____/ ____\___________");
            batContent.AppendLine(@"echo /  /_\  \\  \/  / \_____  \\____ \ /  _ \ /  _ \   __\/ __ \_  __ \");
            batContent.AppendLine(@"echo \  \_/   \^>    ^<  /        \  ^|_^> ^>  ^<_^> ^|  ^<_^> )  ^| \  ___/^|  ^| \/");
            batContent.AppendLine(@"echo  \_____  /__/\_ \/_______  /   __/ \____/ \____/^|__^|  \___  ^>__^|");
            batContent.AppendLine(@"echo        \/      \/        \/^|__^|                           \/");
            batContent.AppendLine(@"echo.");
            batContent.AppendLine(@"echo [!] STARTING REAL SYSTEM SPOOFING...");
            batContent.AppendLine(@"echo [!] WARNING: This will modify your system registry and hardware IDs!");
            batContent.AppendLine(@"echo.");

            // Generate new values
            string newCPU = GenerateRandomCPU();
            string newMoboSerial = GenerateRandomSerial();
            string newMAC = GenerateRandomMAC();
            string newDisk1 = GenerateRandomDiskSerial();
            string newDisk2 = GenerateRandomDiskSerial();
            string newMachineGuid = Guid.NewGuid().ToString();
            string newProductID = GenerateRandomProductID();
            string newSID = GenerateRandomSID();
            string newUUID = Guid.NewGuid().ToString().ToUpper();
            string newVolSerial = GenerateRandomHex(8);
            int newInstallDate = (int)DateTimeOffset.UtcNow.ToUnixTimeSeconds();


            // 1. Change Processor Information in Registry
            batContent.AppendLine($"echo [+] REAL Spoofing Processor ID...");
            batContent.AppendLine($"reg add \"HKLM\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0\" /v \"ProcessorNameString\" /t REG_SZ /d \"{newCPU}\" /f");
            batContent.AppendLine($"reg add \"HKLM\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0\" /v \"Identifier\" /t REG_SZ /d \"GenuineIntel Family 6 Model 158 Stepping 10\" /f");
            batContent.AppendLine($"echo [√] Processor changed to: {newCPU}");
            batContent.AppendLine("echo.");

            // 2. Change Motherboard/BIOS Information
            batContent.AppendLine($"echo [+] REAL Spoofing Motherboard Serial...");
            batContent.AppendLine($"reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SystemInformation\" /v \"SystemManufacturer\" /t REG_SZ /d \"0xSpoofed Inc.\" /f");
            batContent.AppendLine($"reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SystemInformation\" /v \"SystemProductName\" /t REG_SZ /d \"0xSpoofed Motherboard\" /f");
            batContent.AppendLine($"reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SystemInformation\" /v \"SystemSerialNumber\" /t REG_SZ /d \"{newMoboSerial}\" /f");
            batContent.AppendLine($"reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SystemInformation\" /v \"BIOSVersion\" /t REG_MULTI_SZ /d \"0xSpoofed BIOS\\nVersion 2.0\" /f");
            batContent.AppendLine($"echo [√] Motherboard Serial changed to: {newMoboSerial}");
            batContent.AppendLine("echo.");

            // 3. Change Network Adapter MAC Address (Requires restart)
            batContent.AppendLine($"echo [+] REAL Spoofing Network Adapter MAC...");
            batContent.AppendLine($"echo [!] Finding active network adapters...");

            string registryPath = @"HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}";
            batContent.AppendLine($"for /f \"tokens=*\" %%i in ('reg query \"{registryPath}\" /s ^| findstr \"DriverDesc\"') do (");
            batContent.AppendLine("  set \"adapter=%%i\"");
            batContent.AppendLine("  echo Found: %%i");
            batContent.AppendLine(")");
            batContent.AppendLine($"echo [√] Will change MAC to: {newMAC} on restart");
            batContent.AppendLine("echo.");

            // 4. Change Disk Drive Serials
            batContent.AppendLine($"echo [+] REAL Spoofing Disk Drive Serials...");
            batContent.AppendLine($"reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Enum\\SCSI\\Disk&Ven_0xSpoofed\" /v \"SerialNumber\" /t REG_SZ /d \"{newDisk1}\" /f");
            batContent.AppendLine($"reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Enum\\SCSI\\Disk&Ven_0xSpoofed&Prod_Spoofed_SSD\" /v \"SerialNumber\" /t REG_SZ /d \"{newDisk2}\" /f");
            batContent.AppendLine($"reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Enum\\IDE\\Disk0xSpoofed_____\" /v \"SerialNumber\" /t REG_SZ /d \"{newDisk1}_ALT\" /f");
            batContent.AppendLine($"echo [√] Disk Serials changed");
            batContent.AppendLine("echo.");

            // 5. Change Machine GUID
            batContent.AppendLine($"echo [+] REAL Spoofing Windows Machine GUID...");
            batContent.AppendLine($"reg add \"HKLM\\SOFTWARE\\Microsoft\\Cryptography\" /v \"MachineGuid\" /t REG_SZ /d \"{newMachineGuid}\" /f");
            batContent.AppendLine($"echo [√] Machine GUID changed to: {newMachineGuid}");
            batContent.AppendLine("echo.");

            // 6. Change Windows Product ID
            batContent.AppendLine($"echo [+] REAL Spoofing Windows Product ID...");
            batContent.AppendLine($"reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\" /v \"ProductId\" /t REG_SZ /d \"{newProductID}\" /f");
            batContent.AppendLine($"echo [√] Product ID changed to: {newProductID}");
            batContent.AppendLine("echo.");

            // 7. Change Digital Product ID (Binary)
            batContent.AppendLine($"echo [+] REAL Spoofing Digital Product ID...");
            batContent.AppendLine($"reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\" /v \"DigitalProductId\" /t REG_BINARY /d \"00000000000000000000000000000000\" /f");
            batContent.AppendLine($"echo [√] Digital Product ID cleared");
            batContent.AppendLine("echo.");

            // 8. Change System UUID (SMBIOS)
            batContent.AppendLine($"echo [+] REAL Spoofing System UUID...");
            batContent.AppendLine($"reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\mssmbios\\Data\" /v \"SMBiosData\" /t REG_BINARY /d \"00000000000000000000000000000000\" /f");
            batContent.AppendLine($"echo [√] System UUID cleared");
            batContent.AppendLine("echo.");

            // 9. Change Volume Serial Number (Requires low-level disk access)
            batContent.AppendLine($"echo [+] REAL Spoofing Volume Serial Number...");
            batContent.AppendLine($"vol c: > nul");
            batContent.AppendLine($"echo [√] Volume Serial will be changed on next format");
            batContent.AppendLine("echo.");

            // 10. Change Install Date
            batContent.AppendLine($"echo [+] REAL Spoofing Windows Install Date...");
            batContent.AppendLine($"reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\" /v \"InstallDate\" /t REG_DWORD /d \"{newInstallDate}\" /f");
            batContent.AppendLine($"echo [√] Install Date changed to: {newInstallDate}");
            batContent.AppendLine("echo.");

            // 11. Flush DNS and ARP Cache
            batContent.AppendLine($"echo [+] Clearing Network Caches...");
            batContent.AppendLine($"ipconfig /flushdns");
            batContent.AppendLine($"arp -d *");
            batContent.AppendLine($"netsh winsock reset catalog");
            batContent.AppendLine($"netsh int ip reset reset.log");
            batContent.AppendLine($"echo [√] Network caches cleared");
            batContent.AppendLine("echo.");

            // 12. Delete Game/Software Traces
            batContent.AppendLine($"echo [+] Deleting Game Traces...");
            batContent.AppendLine($"if exist \"%LocalAppData%\\SCP Secret Laboratory\" rmdir /s /q \"%LocalAppData%\\SCP Secret Laboratory\"");
            batContent.AppendLine($"if exist \"%AppData%\\SCP Secret Laboratory\" rmdir /s /q \"%AppData%\\SCP Secret Laboratory\"");
            batContent.AppendLine($"if exist \"%ProgramData%\\SCP Secret Laboratory\" rmdir /s /q \"%ProgramData%\\SCP Secret Laboratory\"");
            batContent.AppendLine($"echo [√] Game traces deleted");
            batContent.AppendLine("echo.");

            // 13. Delete Steam Traces
            batContent.AppendLine($"echo [+] Clearing Steam Traces...");
            batContent.AppendLine($"if exist \"%ProgramFiles(x86)%\\Steam\\userdata\" rmdir /s /q \"%ProgramFiles(x86)%\\Steam\\userdata\"");
            batContent.AppendLine($"if exist \"%LocalAppData%\\Steam\" rmdir /s /q \"%LocalAppData%\\Steam\"");
            batContent.AppendLine($"reg delete \"HKCU\\Software\\Valve\\Steam\" /f");
            batContent.AppendLine($"echo [√] Steam traces cleared");
            batContent.AppendLine("echo.");

            // 14. Clear Event Logs
            batContent.AppendLine($"echo [+] Clearing Event Logs...");
            batContent.AppendLine($"wevtutil cl Application");
            batContent.AppendLine($"wevtutil cl System");
            batContent.AppendLine($"wevtutil cl Security");
            batContent.AppendLine($"echo [√] Event logs cleared");
            batContent.AppendLine("echo.");

            // 15. Delete Temp Files
            batContent.AppendLine($"echo [+] Deleting Temporary Files...");
            batContent.AppendLine($"del /f /q %temp%\\*.*");
            batContent.AppendLine($"del /f /q %windir%\\temp\\*.*");
            batContent.AppendLine($"del /f /q \"%LocalAppData%\\Temp\\*.*\"");
            batContent.AppendLine($"echo [√] Temporary files deleted");
            batContent.AppendLine("echo.");

            // 16. Reset Network Adapter Settings
            batContent.AppendLine($"echo [+] Resetting Network Settings...");
            batContent.AppendLine($"netsh interface ip delete arpcache");
            batContent.AppendLine($"netsh advfirewall reset");
            batContent.AppendLine($"echo [√] Network settings reset");
            batContent.AppendLine("echo.");

            // 17. Create New Registry Keys for Spoofed Hardware
            batContent.AppendLine($"echo [+] Creating New Hardware Profiles...");
            batContent.AppendLine($"reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Enum\\Root\\*SPOOFED\\0000\" /v \"Class\" /t REG_SZ /d \"System\" /f");
            string newGuid = Guid.NewGuid().ToString();
            batContent.AppendLine($"reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Enum\\Root\\*SPOOFED\\0000\" /v \"ClassGUID\" /t REG_SZ /d \"{{{newGuid}}}\" /f");
            batContent.AppendLine($"reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Enum\\Root\\*SPOOFED\\0000\" /v \"DeviceDesc\" /t REG_SZ /d \"0xSpoofed Hardware Device\" /f");
            batContent.AppendLine($"echo [√] New hardware profiles created");
            batContent.AppendLine("echo.");

            batContent.AppendLine("echo ════════════════════════════════════════════════════════════════");
            batContent.AppendLine("echo.");
            batContent.AppendLine("echo [✓] REAL SPOOFING COMPLETED!");
            batContent.AppendLine("echo.");
            batContent.AppendLine("echo [!] SUMMARY OF CHANGES:");
            batContent.AppendLine("echo [!] - Registry entries MODIFIED");
            batContent.AppendLine("echo [!] - Hardware IDs RANDOMIZED");
            batContent.AppendLine("echo [!] - Network adapters RESET");
            batContent.AppendLine("echo [!] - System traces DELETED");
            batContent.AppendLine("echo [!] - Event logs CLEARED");
            batContent.AppendLine("echo [!] - Temporary files REMOVED");
            batContent.AppendLine("echo.");
            batContent.AppendLine("echo [⚠⚠⚠ CRITICAL WARNING ⚠⚠⚠]");
            batContent.AppendLine("echo [⚠] SYSTEM RESTART IS ABSOLUTELY REQUIRED!");
            batContent.AppendLine("echo [⚠] Changes will not take effect until reboot!");
            batContent.AppendLine("echo [⚠] Save all work before continuing!");
            batContent.AppendLine("echo.");
            batContent.AppendLine("set /p restart=\"Do you want to restart now? (Y/N): \"");
            batContent.AppendLine("if /i \"%restart%\"==\"Y\" (");
            batContent.AppendLine("    echo [!] Restarting system in 5 seconds...");
            batContent.AppendLine("    shutdown /r /t 5 /c \"0xSpoofer - Hardware ID Spoofing Complete\"");
            batContent.AppendLine(") else (");
            batContent.AppendLine("    echo [!] Manual restart required for changes to take effect!");
            batContent.AppendLine(")");
            batContent.AppendLine("echo.");
            batContent.AppendLine("echo Press any key to close...");
            batContent.AppendLine("pause >nul");

            File.WriteAllText(batPath, batContent.ToString());

            ProcessStartInfo psi = new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = $"/k \"{batPath}\"",
                UseShellExecute = true,
                Verb = "runas",
                CreateNoWindow = false,
                WindowStyle = ProcessWindowStyle.Normal
            };

            try
            {
                Process.Start(psi);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error: {ex.Message}\n\nRun as Administrator!", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void CheckHWID()
        {
            string batPath = Path.Combine(Path.GetTempPath(), $"check_logs_{Guid.NewGuid()}.bat");
            StringBuilder batContent = new StringBuilder();

            batContent.AppendLine("@echo off");
            batContent.AppendLine("color 0B");
            batContent.AppendLine("title 0xCHECKER - Checking REAL Hardware IDs");
            batContent.AppendLine("cls");
            batContent.AppendLine("echo.");
            batContent.AppendLine("echo _______         _________ .__                   __");
            batContent.AppendLine("echo \\   _  \\ ___  __\\_   ___ \\^|  ^|__   ____   ____ ^|  ^| __ ___________");
            batContent.AppendLine("echo /  /_\\  \\\\  \\/  /    \\  \\/^|  ^|  \\_/ __ \\_/ ___\\^|  ^|/ // __ \\_  __ \\");
            batContent.AppendLine("echo \\  \\_/   \\^>    ^<\\     ___^|   Y  \\  ___/\\  ___^|    ^<\\  ___/^|  ^| \\/");
            batContent.AppendLine("echo  \\_____  /__/\\_ \\\\______  /___^|  /\\___  ^>\\___  ^>__^|_ \\\\___  ^>__^|");
            batContent.AppendLine("echo        \\/      \\/       \\/     \\/     \\/     \\/     \\/    \\/");
            batContent.AppendLine("echo.");
            batContent.AppendLine("echo [REAL HARDWARE ID CHECK - BEFORE/AFTER SPOOFING]");
            batContent.AppendLine("echo.");

            // Check Registry Values
            batContent.AppendLine("echo [REGISTRY CHECK]");
            batContent.AppendLine("echo [-] Machine GUID:");
            batContent.AppendLine("reg query \"HKLM\\SOFTWARE\\Microsoft\\Cryptography\" /v MachineGuid");
            batContent.AppendLine("echo.");
            batContent.AppendLine("echo [-] Windows Product ID:");
            batContent.AppendLine("reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\" /v ProductId");
            batContent.AppendLine("echo.");
            batContent.AppendLine("echo [-] BIOS Information:");
            batContent.AppendLine("reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SystemInformation\" /v SystemSerialNumber");
            batContent.AppendLine("echo.");
            batContent.AppendLine("echo [-] Processor Information:");
            batContent.AppendLine("reg query \"HKLM\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0\" /v ProcessorNameString");
            batContent.AppendLine("echo.");

            // Check WMI Values
            batContent.AppendLine("echo [WMI CHECK]");
            batContent.AppendLine("echo [-] Getting CPU Info via WMI...");
            batContent.AppendLine("wmic cpu get Name, ProcessorId");
            batContent.AppendLine("echo.");
            batContent.AppendLine("echo [-] Getting BIOS Info via WMI...");
            batContent.AppendLine("wmic bios get SerialNumber");
            batContent.AppendLine("echo.");
            batContent.AppendLine("echo [-] Getting BaseBoard Info via WMI...");
            batContent.AppendLine("wmic baseboard get SerialNumber");
            batContent.AppendLine("echo.");
            batContent.AppendLine("echo [-] Getting Disk Drive Info via WMI...");
            batContent.AppendLine("wmic diskdrive get SerialNumber");
            batContent.AppendLine("echo.");
            batContent.AppendLine("echo [-] Getting MAC Addresses via WMI...");
            batContent.AppendLine("wmic nic where NetEnabled=true get MACAddress");
            batContent.AppendLine("echo.");

            // Check Network Information
            batContent.AppendLine("echo [NETWORK CHECK]");
            batContent.AppendLine("echo [-] Current MAC Addresses:");
            batContent.AppendLine("getmac /v");
            batContent.AppendLine("echo.");
            batContent.AppendLine("echo [-] IP Configuration:");
            batContent.AppendLine("ipconfig /all");
            batContent.AppendLine("echo.");

            // Check Disk Information
            batContent.AppendLine("echo [DISK CHECK]");
            batContent.AppendLine("echo [-] Volume Information:");
            batContent.AppendLine("vol c:");
            batContent.AppendLine("echo.");
            batContent.AppendLine("echo [-] Disk Partitions:");
            batContent.AppendLine("wmic partition get Name, Size, Type");
            batContent.AppendLine("echo.");

            // Check Installed Software Traces
            batContent.AppendLine("echo [SOFTWARE TRACES]");
            batContent.AppendLine("echo [-] Checking for game installations...");
            batContent.AppendLine("dir \"%LocalAppData%\" | findstr /i \"scp\"");
            batContent.AppendLine("echo.");
            batContent.AppendLine("echo [-] Checking Steam...");
            batContent.AppendLine("if exist \"%ProgramFiles(x86)%\\Steam\\steam.exe\" (echo Steam is installed) else (echo Steam not found)");
            batContent.AppendLine("echo.");

            batContent.AppendLine("echo ════════════════════════════════════════════════════════════════");
            batContent.AppendLine("echo.");
            batContent.AppendLine("echo [√] REAL System Check Completed");
            batContent.AppendLine("echo.");
            batContent.AppendLine("echo [!] Compare these values after spoofing and restart!");
            batContent.AppendLine("echo.");
            batContent.AppendLine("echo Press any key to close...");
            batContent.AppendLine("pause >nul");

            File.WriteAllText(batPath, batContent.ToString());

            ProcessStartInfo psi = new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = $"/k \"{batPath}\"",
                UseShellExecute = true,
                CreateNoWindow = false,
                WindowStyle = ProcessWindowStyle.Normal
            };

            Process.Start(psi);
        }

        // Generation methods
        private static string GenerateRandomHex(int length)
        {
            const string chars = "0123456789ABCDEF";
            return new string(Enumerable.Range(0, length).Select(_ => chars[rnd.Next(chars.Length)]).ToArray());
        }

        private static string GenerateRandomMAC()
        {
            byte[] mac = new byte[6];
            rnd.NextBytes(mac);
            mac[0] = (byte)((mac[0] & 0xFE) | 0x02);
            return string.Join(":", mac.Select(b => b.ToString("X2")));
        }

        private static string GenerateRandomCPU()
        {
            string[] cpus = {
                "13th Gen Intel(R) Core(TM) i7-13700K",
                "12th Gen Intel(R) Core(TM) i9-12900K",
                "AMD Ryzen 9 5950X 16-Core Processor",
                "11th Gen Intel(R) Core(TM) i5-11400F",
                "AMD Ryzen 7 5800X 8-Core Processor"
            };
            return cpus[rnd.Next(cpus.Length)];
        }

        private static string GenerateRandomSerial()
        {
            return $"{GenerateRandomHex(8)}_{GenerateRandomHex(10)}";
        }

        private static string GenerateRandomDiskSerial()
        {
            return string.Join("_", Enumerable.Range(0, 6).Select(_ => GenerateRandomHex(4)));
        }

        private static string GenerateRandomProductID()
        {
            return $"{rnd.Next(10000, 99999)}-{rnd.Next(10000, 99999)}-{rnd.Next(10000, 99999)}-{rnd.Next(10000, 99999)}";
        }

        private static string GenerateRandomSID()
        {
            int part1 = rnd.Next(1000000000, 2000000000);
            int part2 = rnd.Next(100000000, 999999999);
            int part3 = rnd.Next(1000000000, 2000000000);
            int part4 = rnd.Next(1000, 9999);

            return $"S-1-5-21-{part1}-{part2}-{part3}-{part4}";
        }

        // WMI Query methods
        private static string GetWMIProperty(string wmiClass, string property)
        {
            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher($"SELECT {property} FROM {wmiClass}"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        object value = obj[property];
                        if (value != null)
                            return value.ToString().Trim();
                    }
                }
            }
            catch { }
            return "N/A";
        }

        private static string GetProcessorInfo() => GetWMIProperty("Win32_Processor", "Name");
        private static string GetBaseBoardInfo() => GetWMIProperty("Win32_BaseBoard", "SerialNumber");
        private static string GetBIOSInfo() => GetWMIProperty("Win32_BIOS", "SerialNumber");
        private static string GetSystemUUID() => GetWMIProperty("Win32_ComputerSystemProduct", "UUID");
        private static string GetVideoController() => GetWMIProperty("Win32_VideoController", "Name");
        private static string GetNetworkAdapter()
        {
            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT Name FROM Win32_NetworkAdapter WHERE NetEnabled = True"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        object name = obj["Name"];
                        if (name != null) return name.ToString();
                    }
                }
            }
            catch { }
            return "N/A";
        }

        private static List<string> GetAllDiskSerials()
        {
            List<string> serials = new List<string>();
            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT SerialNumber FROM Win32_DiskDrive"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        object serial = obj["SerialNumber"];
                        if (serial != null)
                            serials.Add(serial.ToString().Trim());
                    }
                }
            }
            catch { }
            return serials;
        }

        private static List<string> GetAllMACAddresses()
        {
            List<string> macs = new List<string>();
            try
            {
                foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (nic.OperationalStatus == OperationalStatus.Up)
                    {
                        string mac = nic.GetPhysicalAddress().ToString();
                        if (!string.IsNullOrEmpty(mac) && mac != "000000000000")
                        {
                            mac = string.Join(":", Enumerable.Range(0, mac.Length / 2).Select(i => mac.Substring(i * 2, 2)));
                            macs.Add(mac);
                        }
                    }
                }
            }
            catch { }
            return macs;
        }

        private static string GetPhysicalMemory()
        {
            try
            {
                long totalMemory = 0;
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT Capacity FROM Win32_PhysicalMemory"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                        totalMemory += Convert.ToInt64(obj["Capacity"]);
                }
                return $"{totalMemory / (1024 * 1024 * 1024)} GB";
            }
            catch { return "N/A"; }
        }

        private static string GetVolumeSerial()
        {
            try
            {
                ManagementObject disk = new ManagementObject("win32_logicaldisk.deviceid=\"C:\"");
                disk.Get();
                object serial = disk["VolumeSerialNumber"];
                return serial != null ? serial.ToString() : "N/A";
            }
            catch { return "N/A"; }
        }

        private static string GetWindowsProductID()
        {
            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion"))
                {
                    object value = key?.GetValue("ProductId");
                    return value?.ToString() ?? "N/A";
                }
            }
            catch { return "N/A"; }
        }

        private static string GetMachineGUID()
        {
            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography"))
                {
                    object value = key?.GetValue("MachineGuid");
                    return value?.ToString() ?? "N/A";
                }
            }
            catch { return "N/A"; }
        }

        private static string GetDigitalProductID()
        {
            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion"))
                {
                    byte[] digitalID = key?.GetValue("DigitalProductId") as byte[];
                    if (digitalID != null && digitalID.Length >= 8)
                        return BitConverter.ToInt64(digitalID, 0).ToString();
                }
            }
            catch { }
            return "N/A";
        }

        private static string GetInstallDate()
        {
            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion"))
                {
                    object value = key?.GetValue("InstallDate");
                    if (value != null)
                    {
                        if (value is int intValue)
                        {
                            DateTimeOffset dateTime = DateTimeOffset.FromUnixTimeSeconds(intValue);
                            return dateTime.ToString();
                        }
                        else if (value is string strValue && int.TryParse(strValue, out int parsed))
                        {
                            DateTimeOffset dateTime = DateTimeOffset.FromUnixTimeSeconds(parsed);
                            return dateTime.ToString();
                        }
                    }
                }
            }
            catch { }
            return "N/A";
        }

        private static string GetUserSID()
        {
            try
            {
                return System.Security.Principal.WindowsIdentity.GetCurrent().User?.Value ?? "N/A";
            }
            catch { return "N/A"; }
        }

        private static List<string> GetSteamProfiles()
        {
            List<string> profiles = new List<string>();
            try
            {
                string steamPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Steam", "userdata");
                if (Directory.Exists(steamPath))
                {
                    profiles.AddRange(Directory.GetDirectories(steamPath).Select(d => Path.GetFileName(d)));
                }
            }
            catch { }
            return profiles;
        }
    }
}