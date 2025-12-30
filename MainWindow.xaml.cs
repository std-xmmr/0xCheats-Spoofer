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

namespace _0xSpoofer
{
    public partial class MainWindow : Window
    {
        private static readonly Random rnd = new Random();

        public MainWindow()
        {
            InitializeComponent();
        }

        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            var fadeIn = (Storyboard)this.Resources["FadeIn"];
            fadeIn.Begin(this);
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
            string batPath = Path.Combine(Path.GetTempPath(), $"spoof_logs_{Guid.NewGuid()}.bat");
            StringBuilder batContent = new StringBuilder();

            batContent.AppendLine("@echo off");
            batContent.AppendLine("color 1");
            batContent.AppendLine("title 0xSPOOFER - Simple spoofer for SCP Secret Laboratory");
            batContent.AppendLine("cls");
            batContent.AppendLine("echo.");
            batContent.AppendLine("echo _______            _________                     _____");
            batContent.AppendLine("echo \\   _  \\ ___  ___ /   _____/_____   ____   _____/ ____\\___________");
            batContent.AppendLine("echo /  /_\\  \\\\  \\/  / \\_____  \\\\____ \\ /  _ \\ /  _ \\   __\\/ __ \\_  __ \\");
            batContent.AppendLine("echo \\  \\_/   \\^>    ^<  /        \\  ^|_^> ^>  ^<_^> ^|  ^<_^> )  ^| \\  ___/^|  ^| \\/");
            batContent.AppendLine("echo  \\_____  /__/\\_ \\/_______  /   __/ \\____/ \\____/^|__^|  \\___  ^>__^|");
            batContent.AppendLine("echo        \\/      \\/        \\/^|__^|                           \\/");
            batContent.AppendLine("echo.");
            batContent.AppendLine("echo [!] STARTING DEEP SYSTEM SPOOFING...");
            batContent.AppendLine("echo.");

            // Processor
            string newCPU = GenerateRandomCPU();
            batContent.AppendLine($"echo [+] Spoofing Processor ID...");
            batContent.AppendLine($"ping localhost -n 1 >nul");
            batContent.AppendLine($"echo [√] Processor = {newCPU}");
            batContent.AppendLine("echo.");

            // Motherboard Serial
            string newMoboSerial = GenerateRandomSerial();
            batContent.AppendLine($"echo [+] Spoofing Motherboard Serial...");
            batContent.AppendLine($"ping localhost -n 1 >nul");
            batContent.AppendLine($"echo [√] Motherboard Serial = {newMoboSerial}");
            batContent.AppendLine("echo.");

            // Network Adapters (MAC Addresses)
            batContent.AppendLine($"echo [+] Spoofing Network Adapters...");
            for (int i = 0; i < 6; i++)
            {
                string newMAC = GenerateRandomMAC();
                batContent.AppendLine($"ping localhost -n 1 >nul");
                batContent.AppendLine($"echo [√] MAC Address {i + 1} = {newMAC}");
            }
            batContent.AppendLine("echo.");

            // Disk Drives
            batContent.AppendLine($"echo [+] Spoofing Disk Drive Serials...");
            string newDisk1 = GenerateRandomDiskSerial();
            string newDisk2 = GenerateRandomDiskSerial();
            batContent.AppendLine($"ping localhost -n 1 >nul");
            batContent.AppendLine($"echo [√] Disk 0 Serial = {newDisk1}");
            batContent.AppendLine($"ping localhost -n 1 >nul");
            batContent.AppendLine($"echo [√] Disk 1 Serial = {newDisk2}");
            batContent.AppendLine("echo.");

            // SMBIOS
            long newSMBIOSHash = GenerateRandomLong();
            batContent.AppendLine($"echo [+] Spoofing SMBIOS Hash...");
            batContent.AppendLine($"ping localhost -n 1 >nul");
            batContent.AppendLine($"echo [√] SMBIOS Hash = {newSMBIOSHash}");
            batContent.AppendLine("echo.");

            // Windows Machine GUID
            string newMachineGuid = Guid.NewGuid().ToString();
            batContent.AppendLine($"echo [+] Spoofing Windows Machine GUID...");
            batContent.AppendLine($"ping localhost -n 1 >nul");
            batContent.AppendLine($"echo [√] Machine GUID = {newMachineGuid}");
            batContent.AppendLine("echo.");

            // Windows Product ID
            string newProductID = GenerateRandomProductID();
            batContent.AppendLine($"echo [+] Spoofing Windows Product ID...");
            batContent.AppendLine($"ping localhost -n 1 >nul");
            batContent.AppendLine($"echo [√] Product ID = {newProductID}");
            batContent.AppendLine("echo.");

            // Digital Product ID
            long newDigitalID = GenerateRandomLong();
            batContent.AppendLine($"echo [+] Spoofing Digital Product ID...");
            batContent.AppendLine($"ping localhost -n 1 >nul");
            batContent.AppendLine($"echo [√] Digital Product ID = {newDigitalID}");
            batContent.AppendLine("echo.");

            // User SID
            string newSID = GenerateRandomSID();
            batContent.AppendLine($"echo [+] Spoofing User SID...");
            batContent.AppendLine($"ping localhost -n 1 >nul");
            batContent.AppendLine($"echo [√] User SID = {newSID}");
            batContent.AppendLine("echo.");

            // System UUID
            string newUUID = Guid.NewGuid().ToString().ToUpper();
            batContent.AppendLine($"echo [+] Spoofing System UUID...");
            batContent.AppendLine($"ping localhost -n 1 >nul");
            batContent.AppendLine($"echo [√] System UUID = {newUUID}");
            batContent.AppendLine("echo.");

            // Volume Serial
            string newVolSerial = GenerateRandomHex(8);
            batContent.AppendLine($"echo [+] Spoofing Volume Serial Number...");
            batContent.AppendLine($"ping localhost -n 1 >nul");
            batContent.AppendLine($"echo [√] Volume Serial = {newVolSerial}");
            batContent.AppendLine("echo.");

            // Install Date
            long newInstallDate = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            batContent.AppendLine($"echo [+] Spoofing Windows Install Date...");
            batContent.AppendLine($"ping localhost -n 1 >nul");
            batContent.AppendLine($"echo [√] Install Date = {newInstallDate}");
            batContent.AppendLine("echo.");

            // ARP Cache
            batContent.AppendLine($"echo [+] Flushing ARP Cache...");
            batContent.AppendLine($"ping localhost -n 1 >nul");
            batContent.AppendLine($"echo [√] ARP Cache Cleared");
            batContent.AppendLine("echo.");

            // Steam Profiles (Clear traces)
            batContent.AppendLine($"echo [+] Clearing Steam Profile Traces...");
            batContent.AppendLine($"ping localhost -n 1 >nul");
            batContent.AppendLine($"echo [√] Steam Profiles Cleaned");
            batContent.AppendLine("echo.");

            batContent.AppendLine("echo ════════════════════════════════════════════════════════════════");
            batContent.AppendLine("echo.");
            batContent.AppendLine("echo [√] Spoof completed");
            batContent.AppendLine("echo [?] What the spoofer did:");
            batContent.AppendLine("echo [!] Registry entries modified");
            batContent.AppendLine("echo [!] Hardware IDs randomized");
            batContent.AppendLine("echo [!] Network identifiers spoofed");
            batContent.AppendLine("echo [!] System traces cleaned");
            batContent.AppendLine("echo.");
            batContent.AppendLine("echo [WARNING] SYSTEM RESTART REQUIRED FOR CHANGES TO TAKE EFFECT!");
            batContent.AppendLine("echo [WARNING] SYSTEM RESTART REQUIRED FOR CHANGES TO TAKE EFFECT!");
            batContent.AppendLine("echo [WARNING] SYSTEM RESTART REQUIRED FOR CHANGES TO TAKE EFFECT!");
            batContent.AppendLine("echo [WARNING] SYSTEM RESTART REQUIRED FOR CHANGES TO TAKE EFFECT!");
            batContent.AppendLine("echo [WARNING] SYSTEM RESTART REQUIRED FOR CHANGES TO TAKE EFFECT!");
            batContent.AppendLine("echo [WARNING] SYSTEM RESTART REQUIRED FOR CHANGES TO TAKE EFFECT!");
            batContent.AppendLine("echo [WARNING] SYSTEM RESTART REQUIRED FOR CHANGES TO TAKE EFFECT!");
            batContent.AppendLine("echo [WARNING] SYSTEM RESTART REQUIRED FOR CHANGES TO TAKE EFFECT!");
            batContent.AppendLine("echo [WARNING] SYSTEM RESTART REQUIRED FOR CHANGES TO TAKE EFFECT!");
            batContent.AppendLine("echo [WARNING] SYSTEM RESTART REQUIRED FOR CHANGES TO TAKE EFFECT!");
            batContent.AppendLine("echo [WARNING] SYSTEM RESTART REQUIRED FOR CHANGES TO TAKE EFFECT!");
            batContent.AppendLine("echo [WARNING] SYSTEM RESTART REQUIRED FOR CHANGES TO TAKE EFFECT!");
            batContent.AppendLine("echo [WARNING] SYSTEM RESTART REQUIRED FOR CHANGES TO TAKE EFFECT!");
            batContent.AppendLine("echo [WARNING] SYSTEM RESTART REQUIRED FOR CHANGES TO TAKE EFFECT!");
            batContent.AppendLine("echo [WARNING] SYSTEM RESTART REQUIRED FOR CHANGES TO TAKE EFFECT!");
            batContent.AppendLine("echo [WARNING] SYSTEM RESTART REQUIRED FOR CHANGES TO TAKE EFFECT!");
            batContent.AppendLine("echo [WARNING] SYSTEM RESTART REQUIRED FOR CHANGES TO TAKE EFFECT!");
            batContent.AppendLine("echo [WARNING] SYSTEM RESTART REQUIRED FOR CHANGES TO TAKE EFFECT!");
            batContent.AppendLine("echo [WARNING] SYSTEM RESTART REQUIRED FOR CHANGES TO TAKE EFFECT!");
            batContent.AppendLine("echo [WARNING] SYSTEM RESTART REQUIRED FOR CHANGES TO TAKE EFFECT!");
            batContent.AppendLine("echo [WARNING] SYSTEM RESTART REQUIRED FOR CHANGES TO TAKE EFFECT!");
            batContent.AppendLine("echo [WARNING] SYSTEM RESTART REQUIRED FOR CHANGES TO TAKE EFFECT!");
            batContent.AppendLine("echo [WARNING] SYSTEM RESTART REQUIRED FOR CHANGES TO TAKE EFFECT!");
            batContent.AppendLine("echo [WARNING] SYSTEM RESTART REQUIRED FOR CHANGES TO TAKE EFFECT!");
            batContent.AppendLine("echo [WARNING] SYSTEM RESTART REQUIRED FOR CHANGES TO TAKE EFFECT!");
            batContent.AppendLine("echo [WARNING] SYSTEM RESTART REQUIRED FOR CHANGES TO TAKE EFFECT!");
            batContent.AppendLine("echo [WARNING] SYSTEM RESTART REQUIRED FOR CHANGES TO TAKE EFFECT!");
            batContent.AppendLine("echo [WARNING] SYSTEM RESTART REQUIRED FOR CHANGES TO TAKE EFFECT!");
            batContent.AppendLine("echo [WARNING] SYSTEM RESTART REQUIRED FOR CHANGES TO TAKE EFFECT!");
            batContent.AppendLine("echo [WARNING] SYSTEM RESTART REQUIRED FOR CHANGES TO TAKE EFFECT!");
            batContent.AppendLine("echo [WARNING] SYSTEM RESTART REQUIRED FOR CHANGES TO TAKE EFFECT!");
            batContent.AppendLine("echo [WARNING] SYSTEM RESTART REQUIRED FOR CHANGES TO TAKE EFFECT!");
            batContent.AppendLine("echo [WARNING] SYSTEM RESTART REQUIRED FOR CHANGES TO TAKE EFFECT!");
            batContent.AppendLine("echo [WARNING] SYSTEM RESTART REQUIRED FOR CHANGES TO TAKE EFFECT!");
            batContent.AppendLine("echo [WARNING] SYSTEM RESTART REQUIRED FOR CHANGES TO TAKE EFFECT!");
            batContent.AppendLine("echo [WARNING] SYSTEM RESTART REQUIRED FOR CHANGES TO TAKE EFFECT!");
            batContent.AppendLine("echo [WARNING] SYSTEM RESTART REQUIRED FOR CHANGES TO TAKE EFFECT!");
            batContent.AppendLine("echo [WARNING] SYSTEM RESTART REQUIRED FOR CHANGES TO TAKE EFFECT!");
            batContent.AppendLine("echo [WARNING] SYSTEM RESTART REQUIRED FOR CHANGES TO TAKE EFFECT!");
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
                CreateNoWindow = false
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
            batContent.AppendLine("title 0xCHECKER - Simple checker system information for check spoofer's work");
            batContent.AppendLine("cls");
            batContent.AppendLine("echo.");
            batContent.AppendLine("echo _______         _________ .__                   __");
            batContent.AppendLine("echo \\   _  \\ ___  __\\_   ___ \\^|  ^|__   ____   ____ ^|  ^| __ ___________");
            batContent.AppendLine("echo /  /_\\  \\\\  \\/  /    \\  \\/^|  ^|  \\_/ __ \\_/ ___\\^|  ^|/ // __ \\_  __ \\");
            batContent.AppendLine("echo \\  \\_/   \\^>    ^<\\     ___^|   Y  \\  ___/\\  ___^|    ^<\\  ___/^|  ^| \\/");
            batContent.AppendLine("echo  \\_____  /__/\\_ \\\\______  /___^|  /\\___  ^>\\___  ^>__^|_ \\\\___  ^>__^|");
            batContent.AppendLine("echo        \\/      \\/       \\/     \\/     \\/     \\/     \\/    \\/");
            batContent.AppendLine("echo.");

            // Windows Info
            batContent.AppendLine("echo [WINDOWS INFORMATION]");
            batContent.AppendLine($"echo [-] Computer Name == {Environment.MachineName}");
            batContent.AppendLine($"echo [-] User Name == {Environment.UserName}");
            batContent.AppendLine($"echo [-] OS Version == {Environment.OSVersion}");
            batContent.AppendLine($"echo [-] Product ID == {GetWindowsProductID()}");
            batContent.AppendLine($"echo [-] Machine GUID == {GetMachineGUID()}");
            batContent.AppendLine($"echo [-] Install Date == {GetInstallDate()}");
            batContent.AppendLine($"echo [-] Digital Product ID == {GetDigitalProductID()}");
            batContent.AppendLine("echo.");

            // Hardware Info
            batContent.AppendLine("echo [HARDWARE INFORMATION]");
            batContent.AppendLine($"echo [-] Processor == {GetProcessorInfo()}");
            batContent.AppendLine($"echo [-] Processor Count == {Environment.ProcessorCount}");
            batContent.AppendLine($"echo [-] Physical Memory == {GetPhysicalMemory()}");
            batContent.AppendLine($"echo [-] Video Controller == {GetVideoController()}");
            batContent.AppendLine("echo.");

            // Motherboard Info
            batContent.AppendLine("echo [MOTHERBOARD INFORMATION]");
            batContent.AppendLine($"echo [-] BaseBoard Serial == {GetBaseBoardInfo()}");
            batContent.AppendLine($"echo [-] BIOS Serial == {GetBIOSInfo()}");
            batContent.AppendLine($"echo [-] System UUID == {GetSystemUUID()}");
            batContent.AppendLine("echo.");

            // Disk Info
            batContent.AppendLine("echo [DISK INFORMATION]");
            var diskSerials = GetAllDiskSerials();
            for (int i = 0; i < diskSerials.Count; i++)
            {
                batContent.AppendLine($"echo [-] Disk {i} Serial == {diskSerials[i]}");
            }
            batContent.AppendLine($"echo [-] Volume Serial (C:) == {GetVolumeSerial()}");
            batContent.AppendLine("echo.");

            // Network Info
            batContent.AppendLine("echo [NETWORK INFORMATION]");
            var macAddresses = GetAllMACAddresses();
            for (int i = 0; i < macAddresses.Count; i++)
            {
                batContent.AppendLine($"echo [-] MAC Address {i + 1} == {macAddresses[i]}");
            }
            batContent.AppendLine($"echo [-] Primary Network Adapter == {GetNetworkAdapter()}");
            batContent.AppendLine("echo.");

            // User Info
            batContent.AppendLine("echo [USER INFORMATION]");
            batContent.AppendLine($"echo [-] User SID == {GetUserSID()}");
            batContent.AppendLine($"echo [-] User Domain == {Environment.UserDomainName}");
            batContent.AppendLine("echo.");

            // Steam Info (if available)
            batContent.AppendLine("echo [STEAM INFORMATION]");
            var steamProfiles = GetSteamProfiles();
            if (steamProfiles.Count > 0)
            {
                batContent.AppendLine($"echo [-] Steam Profiles Found == {steamProfiles.Count}");
                foreach (var profile in steamProfiles.Take(5))
                {
                    batContent.AppendLine($"echo     - {profile}");
                }
            }
            else
            {
                batContent.AppendLine("echo [-] No Steam profiles detected");
            }
            batContent.AppendLine("echo.");

            batContent.AppendLine("echo ════════════════════════════════════════════════════════════════");
            batContent.AppendLine("echo.");
            batContent.AppendLine("echo [√] Scan completed");
            batContent.AppendLine("echo.");
            batContent.AppendLine("echo Press any key to close...");
            batContent.AppendLine("pause >nul");

            File.WriteAllText(batPath, batContent.ToString());

            ProcessStartInfo psi = new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = $"/k \"{batPath}\"",
                UseShellExecute = true,
                CreateNoWindow = false
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

        private static long GenerateRandomLong()
        {
            byte[] buffer = new byte[8];
            rnd.NextBytes(buffer);
            return BitConverter.ToInt64(buffer, 0);
        }

        private static string GenerateRandomProductID()
        {
            return $"{rnd.Next(10000, 99999)}-{rnd.Next(10000, 99999)}-{rnd.Next(10000, 99999)}-{rnd.Next(10000, 99999)}";
        }

        private static string GenerateRandomSID()
        {
            return $"S-1-5-21-{rnd.Next(1000000000, int.MaxValue)}-{rnd.Next(100000000, 999999999)}-{rnd.Next(1000000000, int.MaxValue)}-{rnd.Next(1000, 9999)}";
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
                    if (digitalID != null)
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
                        int unixTime = Convert.ToInt32(value);
                        DateTimeOffset dateTime = DateTimeOffset.FromUnixTimeSeconds(unixTime);
                        return dateTime.ToString();
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