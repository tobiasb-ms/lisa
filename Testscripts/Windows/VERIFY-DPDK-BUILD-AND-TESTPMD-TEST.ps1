# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache License.

function Main {
    # Create test result
    $superUser = "root"
    $resultArr = @()

    try {
        $noClient = $true
        $noServer = $true
        foreach ($vmData in $allVMData) {
            if ($vmData.RoleName -imatch "client") {
                $clientVMData = $vmData
                $noClient = $false
            }
            elseif ($vmData.RoleName -imatch "server") {
                $noServer = $fase
                $serverVMData = $vmData
            }
        }
        if ($noClient) {
            Throw "No any master VM defined. Be sure that, Client VM role name matches with the pattern `"*master*`". Aborting Test."
        }
        if ($noServer) {
            Throw "No any slave VM defined. Be sure that, Server machine role names matches with pattern `"*slave*`" Aborting Test."
        }
        #region CONFIGURE VM FOR TERASORT TEST
        LogMsg "CLIENT VM details :"
        LogMsg "  RoleName : $($clientVMData.RoleName)"
        LogMsg "  Public IP : $($clientVMData.PublicIP)"
        LogMsg "  SSH Port : $($clientVMData.SSHPort)"
        LogMsg "  Internal IP : $($clientVMData.InternalIP)"
        LogMsg "SERVER VM details :"
        LogMsg "  RoleName : $($serverVMData.RoleName)"
        LogMsg "  Public IP : $($serverVMData.PublicIP)"
        LogMsg "  SSH Port : $($serverVMData.SSHPort)"
        LogMsg "  Internal IP : $($serverVMData.InternalIP)"

        # PROVISION VMS FOR LISA WILL ENABLE ROOT USER AND WILL MAKE ENABLE PASSWORDLESS AUTHENTICATION ACROSS ALL VMS IN SAME HOSTED SERVICE.
        ProvisionVMsForLisa -allVMData $allVMData -installPackagesOnRoleNames "none"
        #endregion

        LogMsg "Getting Active NIC Name."
        $getNicCmd = ". ./utils.sh &> /dev/null && get_active_nic_name"
        $clientNicName = (RunLinuxCmd -ip $clientVMData.PublicIP -port $clientVMData.SSHPort -username $superUser -password $password -command $getNicCmd).Trim()
        $serverNicName = (RunLinuxCmd -ip $clientVMData.PublicIP -port $serverVMData.SSHPort -username $superUser -password $password -command $getNicCmd).Trim()
        if ($serverNicName -eq $clientNicName) {
            LogMsg "Client and Server VMs have same nic name: $clientNicName"
        } else {
            Throw "Server and client SRIOV NICs are not same."
        }
        if($EnableAcceleratedNetworking -or ($currentTestData.AdditionalHWConfig.Networking -imatch "SRIOV")) {
            $DataPath = "SRIOV"
        } else {
            $DataPath = "Synthetic"
        }
        LogMsg "CLIENT $DataPath NIC: $clientNicName"
        LogMsg "SERVER $DataPath NIC: $serverNicName"

        LogMsg "Generating constansts.sh ..."
        $constantsFile = "$LogDir\constants.sh"
        Set-Content -Value "#Generated by Azure Automation." -Path $constantsFile
        Add-Content -Value "vms=$($serverVMData.RoleName),$($clientVMData.RoleName)" -Path $constantsFile
        Add-Content -Value "server=$($serverVMData.InternalIP)" -Path $constantsFile
        Add-Content -Value "client=$($clientVMData.InternalIP)" -Path $constantsFile
        Add-Content -Value "nicName=eth1" -Path $constantsFile
        Add-Content -Value "pciAddress=0002:00:02.0" -Path $constantsFile

        foreach ($param in $currentTestData.TestParameters.param) {
            Add-Content -Value "$param" -Path $constantsFile
            if ($param -imatch "modes") {
                $modes = ($param.Replace("modes=",""))
            }
        }
        LogMsg "constanst.sh created successfully..."
        LogMsg "test modes : $modes"
        LogMsg (Get-Content -Path $constantsFile)
        #endregion

        #region EXECUTE TEST
        $myString = @"
cd /root/
./dpdkTestPmd.sh 2>&1 > dpdkConsoleLogs.txt
. utils.sh
collect_VM_properties
"@
        Set-Content "$LogDir\StartDpdkTestPmd.sh" $myString
        RemoteCopy -uploadTo $clientVMData.PublicIP -port $clientVMData.SSHPort -files "$constantsFile,$LogDir\StartDpdkTestPmd.sh" -username $superUser -password $password -upload

        RunLinuxCmd -ip $clientVMData.PublicIP -port $clientVMData.SSHPort -username $superUser -password $password -command "chmod +x *.sh" | Out-Null
        $testJob = RunLinuxCmd -ip $clientVMData.PublicIP -port $clientVMData.SSHPort -username $superUser -password $password -command "./StartDpdkTestPmd.sh" -RunInBackground
        #endregion

        #region MONITOR TEST
        while ((Get-Job -Id $testJob).State -eq "Running") {
            $currentStatus = RunLinuxCmd -ip $clientVMData.PublicIP -port $clientVMData.SSHPort -username $superUser -password $password -command "tail -2 dpdkConsoleLogs.txt | head -1"
            LogMsg "Current Test Status : $currentStatus"
            WaitFor -seconds 20
        }
        $finalStatus = RunLinuxCmd -ip $clientVMData.PublicIP -port $clientVMData.SSHPort -username $superUser -password $password -command "cat /root/state.txt"
        RemoteCopy -downloadFrom $clientVMData.PublicIP -port $clientVMData.SSHPort -username $superUser -password $password -download -downloadTo $LogDir -files "*.csv, *.txt, *.log"

        if ($finalStatus -imatch "TestFailed") {
            LogErr "Test failed. Last known status : $currentStatus."
            $testResult = "FAIL"
        }
        elseif ($finalStatus -imatch "TestAborted") {
            LogErr "Test Aborted. Last known status : $currentStatus."
            $testResult = "ABORTED"
        }
        elseif ($finalStatus -imatch "TestCompleted") {
            LogMsg "Test Completed."
            $testResult = "PASS"
            RemoteCopy -downloadFrom $clientVMData.PublicIP -port $clientVMData.SSHPort -username $superUser -password $password -download -downloadTo $LogDir -files "*.tar.gz"
        }
        elseif ($finalStatus -imatch "TestRunning") {
            LogMsg "Powershell backgroud job for test is completed but VM is reporting that test is still running. Please check $LogDir\zkConsoleLogs.txt"
            LogMsg "Contests of summary.log : $testSummary"
            $testResult = "PASS"
        }

        try {
            $testpmdDataCsv = Import-Csv -Path $LogDir\dpdkTestPmd.csv
            LogMsg "Uploading the test results.."
            $dataSource = $xmlConfig.config.Azure.database.server
            $DBuser = $xmlConfig.config.Azure.database.user
            $DBpassword = $xmlConfig.config.Azure.database.password
            $database = $xmlConfig.config.Azure.database.dbname
            $dataTableName = $xmlConfig.config.Azure.database.dbtable
            $TestCaseName = $xmlConfig.config.Azure.database.testTag

            if ($dataSource -And $DBuser -And $DBpassword -And $database -And $dataTableName) {
                $GuestDistro = Get-Content "$LogDir\VM_properties.csv" | Select-String "OS type"| ForEach-Object {$_ -replace ",OS type,",""}
                $HostType = "Azure"
                $HostBy = ($xmlConfig.config.Azure.General.Location).Replace('"','')
                $HostOS = Get-Content "$LogDir\VM_properties.csv" | Select-String "Host Version"| ForEach-Object {$_ -replace ",Host Version,",""}
                $GuestOSType = "Linux"
                $GuestDistro = Get-Content "$LogDir\VM_properties.csv" | Select-String "OS type"| ForEach-Object {$_ -replace ",OS type,",""}
                $GuestSize = $clientVMData.InstanceSize
                $KernelVersion = Get-Content "$LogDir\VM_properties.csv" | Select-String "Kernel version"| ForEach-Object {$_ -replace ",Kernel version,",""}
                $IPVersion = "IPv4"
                $ProtocolType = "TCP"
                $connectionString = "Server=$dataSource;uid=$DBuser; pwd=$DBpassword;Database=$database;Encrypt=yes;TrustServerCertificate=no;Connection Timeout=30;"

                $SQLQuery = "INSERT INTO $dataTableName (TestPlatFrom,TestCaseName,TestDate,HostType,HostBy,HostOS,GuestOSType,GuestDistro,GuestSize,KernelVersion,LISVersion,IPVersion,ProtocolType,DataPath,DPDKVersion,TestMode,Cores,Max_Rxpps,Txpps,Rxpps,Fwdpps,Txbytes,Rxbytes,Fwdbytes,Txpackets,Rxpackets,Fwdpackets,Tx_PacketSize_KBytes,Rx_PacketSize_KBytes) VALUES "
                foreach ($mode in $testpmdDataCsv) {
                    $SQLQuery += "('$TestPlatform','$TestCaseName','$(Get-Date -Format yyyy-MM-dd)','$HostType','$HostBy','$HostOS','$GuestOSType','$GuestDistro','$GuestSize','$KernelVersion','Inbuilt','$IPVersion','$ProtocolType','$DataPath','$($mode.DpdkVersion)','$($mode.TestMode)','$($mode.Cores)','$($mode.MaxRxPps)','$($mode.TxPps)','$($mode.RxPps)','$($mode.FwdPps)','$($mode.TxBytes)','$($mode.RxBytes)','$($mode.FwdBytes)','$($mode.TxPackets)','$($mode.RxPackets)','$($mode.FwdPackets)','$($mode.TxPacketSize)','$($mode.RxPacketSize)'),"
                    LogMsg "Collected performace data for $($mode.TestMode) mode."
                }
                $SQLQuery = $SQLQuery.TrimEnd(',')
                LogMsg $SQLQuery
                $connection = New-Object System.Data.SqlClient.SqlConnection
                $connection.ConnectionString = $connectionString
                $connection.Open()

                $command = $connection.CreateCommand()
                $command.CommandText = $SQLQuery

                $command.executenonquery() | Out-Null
                $connection.Close()
                LogMsg "Uploading the test results done!!"
            } else {
                LogErr "Invalid database details. Failed to upload result to database!"
                $ErrorMessage =  $_.Exception.Message
                $ErrorLine = $_.InvocationInfo.ScriptLineNumber
                LogErr "EXCEPTION : $ErrorMessage at line: $ErrorLine"
            }
        } catch {
            $ErrorMessage =  $_.Exception.Message
            throw "$ErrorMessage"
            $testResult = "FAIL"
        }
        LogMsg "Test result : $testResult"
        LogMsg ($testpmdDataCsv | Format-Table | Out-String)
    } catch {
        $ErrorMessage =  $_.Exception.Message
        $ErrorLine = $_.InvocationInfo.ScriptLineNumber
        LogErr "EXCEPTION : $ErrorMessage at line: $ErrorLine"
        $testResult = "FAIL"
    } finally {
        if (!$testResult) {
            $testResult = "Aborted"
        }
        $resultArr += $testResult
    }
    $currentTestResult.TestResult = GetFinalResultHeader -resultarr $resultArr
    return $currentTestResult.TestResult
}

Main
