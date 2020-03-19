# RSA key-based PowerShell 7 SSH remoting

# Overview

Use PowerShell SSH remoting from Windows 10 to Windows 2012 Server

## Why

1. Remotely login and administer computers without providing credentials.
2. Works with machines that are in a workgroup(Non-AD) as well as on machines that are in different domains.
3. Works across various operating systems
    1. Windows → Mac OS or Linux
    2. Linux or Mac OS → Windows
4. placeholder

## Assumptions

PowerShell 7 has been installed on both the client as well as the server and the install path is :

`C:\Program Files\PowerShell\7`

## On Windows 10 - Client

### Install OpenSSH

1. OpenSSH feature is built into Windows 10 `build version` 1809 and above .The feature just needs to be enabled.
2. To check the Windows 10 build version type `Winver` in PowerShell .

    ![https://s3-us-west-2.amazonaws.com/secure.notion-static.com/d8384c36-416e-4221-b514-270510f1e978/Untitled.png](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/d8384c36-416e-4221-b514-270510f1e978/Untitled.png)

3. Open PowerShell as Administrator and type

        Get-WindowsCapability -Online | where Name -like 'OpenSSH*'

    ![https://s3-us-west-2.amazonaws.com/secure.notion-static.com/d7d23012-f37e-44ae-ad7a-7d4727cd812f/Untitled.png](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/d7d23012-f37e-44ae-ad7a-7d4727cd812f/Untitled.png)

4. If the `state` of the `openssh.client` is `NotPresent` then we need to install it.

        Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0

    In order to SSH from Windows 10 to a remote machine we dont need to enable the OpenSSH.Server role on Windows 10. We just need the client enabled or installed.

5. Placeholder

### Configure the SSH Client

1. Set the service to start Automatically

        Set-Service ssh-agent -StartupType Automatic

2. Start the service

        Start-Service ssh-agent -PassThru

3. Placeholder

### Generate RSA Key-Pair

1. Change to the the user profile ssh directory

        cd $home\.ssh

2. Generate the Public-Private key pair.

        ssh-keygen.exe -t rsa

3. You will be prompted to provide a password to secure the private key. Hit enter to continue without providing a password.

    `Enter passphrase (empty for no passphrase):`
    `Enter same passphrase again:`

4. sample output

        PS C:\Users\kiran\.ssh> ssh-keygen.exe -t rsa                                                                                                                                                                  Generating public/private rsa key pair.
        Enter file in which to save the key (C:\Users\kiran/.ssh/id_rsa):
        Enter passphrase (empty for no passphrase):
        Enter same passphrase again:
        Your identification has been saved in C:\Users\kiran/.ssh/id_rsa.
        Your public key has been saved in C:\Users\kiran/.ssh/id_rsa.pub.
        The key fingerprint is:
        SHA256:x5H0LQ29b4favJIxmSKlmYe42JzHJxgEZXaPuX69asQ lab\kiran@KIRAN-Laptop
        The key's randomart image is:
        +---[RSA 2048]----+
        |     .+ . . ..   |
        |    .o . = o +.  |
        |     .  o + o o. |
        |      .  o.. ..  |
        |     . .SBo  o o |
        |      o.*.E.= . +|
        |     + *.+...B ..|
        |    . * +.o +.o  |
        |       . +...... |
        +----[SHA256]-----+
        PS C:\Users\kiran\.ssh> dir

            Directory: C:\Users\kiran\.ssh


        Mode                LastWriteTime         Length Name
        ----                -------------         ------ ----
        -a----        3/18/2020   2:50 PM           1675 id_rsa
        -a----        3/18/2020   2:50 PM            410 id_rsa.pub
        -a----        3/18/2020  10:58 AM            204 known_hosts

5. You should see the following 2 files in the .ssh directory
    1. id_rsa        ⇒ Private Key
    2. id_rsa.pub ⇒ Public Key

6. Placeholder

## On Windows 2012 - Server

### Install OpenSSH

1. Donwload the latest version of OpenSSH from [Github](https://github.com/PowerShell/Win32-OpenSSH/releases/tag/v8.1.0.0p1-Beta)
2. Extract contents of the latest build to C:\Program Files\OpenSSH (Make sure binary location has the Write permissions to just to SYSTEM, Administrator groups. Authenticated users should and only have Read and Execute.)
3. From an elevated PowerShell Install SSH:

        PS C:\Program Files\OpenSSH> .\install-sshd.ps1

4. Open the firewall for sshd.exe to allow inbound SSH connections

        New-NetFirewallRule -Name sshd -DisplayName 'SSH Inbound' -Profile @('Domain', 'Private') -Enabled True -Direction Inbound -Action Allow -Protocol TCP ‑LocalPort 22

5. Placeholder

### Configure the SSH server service

1. Set the service to start Automatically

        Set-Service sshd -StartupType Automatic

2. Start the service

        Start-Service sshd -PassThru

3. Placeholder

### Configure the SSH server Shell

1. The default shell used by SSH is the Windows command shell. We change to PowerShell:

        New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value "C:\Program Files\PowerShell\7\pwsh.exe" -PropertyType String -Force

2. There's a bug in OpenSSH on Windows. It doesn't work with paths with a space.  For more information, see this **[GitHub issue](https://github.com/PowerShell/Win32-OpenSSH/issues/784)**. The workaround is to create a symbolic link that creates a path that OpenSSH can use:

        New-Item -ItemType SymbolicLink -Path C:\pwsh -Target 'C:\Program Files\PowerShell\7'


    **OR**


3.  You can use the 8.3 short name for any file paths that contain spaces. The 8.3 short name for the `Program Files` folder in Windows is usually `Progra~1`.

    We will Use the path below in the sshd_config file.

        c:/progra~1/powershell/7/pwsh.exe

4. Placeholder

### Configure the SSH server sshd_config file

1. The SSH keys and configuration file reside in C:\ProgramData\ssh, which is a hidden folder. edit the config file sshd_config file as follows:

        # This is the sshd server system-wide configuration file.  See
        # sshd_config(5) for more information.

        # The strategy used for options in the default sshd_config shipped with
        # OpenSSH is to specify options with their default value where
        # possible, but leave them commented.  Uncommented options override the
        # default value.

        #Port 22
        #AddressFamily any
        #ListenAddress 0.0.0.0
        #ListenAddress ::

        #HostKey __PROGRAMDATA__/ssh/ssh_host_rsa_key
        #HostKey __PROGRAMDATA__/ssh/ssh_host_dsa_key
        #HostKey __PROGRAMDATA__/ssh/ssh_host_ecdsa_key
        #HostKey __PROGRAMDATA__/ssh/ssh_host_ed25519_key

        # Ciphers and keying
        #RekeyLimit default none

        # Logging
        #SyslogFacility AUTH
        #LogLevel INFO

        # Authentication:

        #LoginGraceTime 2m
        #PermitRootLogin prohibit-password
        StrictModes no
        #MaxAuthTries 6
        #MaxSessions 10

        PubkeyAuthentication yes

        # The default is to check both .ssh/authorized_keys and .ssh/authorized_keys2
        # but this is overridden so installations will only check .ssh/authorized_keys
        AuthorizedKeysFile	.ssh/authorized_keys

        #AuthorizedPrincipalsFile none

        # For this to work you will also need host keys in %programData%/ssh/ssh_known_hosts
        #HostbasedAuthentication no
        # Change to yes if you don't trust ~/.ssh/known_hosts for
        # HostbasedAuthentication
        #IgnoreUserKnownHosts no
        # Don't read the user's ~/.rhosts and ~/.shosts files
        #IgnoreRhosts yes

        # To disable tunneled clear text passwords, change to no here!
        PasswordAuthentication yes
        #PermitEmptyPasswords no

        # GSSAPI options
        #GSSAPIAuthentication no

        #AllowAgentForwarding yes
        #AllowTcpForwarding yes
        #GatewayPorts no
        #PermitTTY yes
        #PrintMotd yes
        #PrintLastLog yes
        #TCPKeepAlive yes
        #UseLogin no
        #PermitUserEnvironment no
        #ClientAliveInterval 0
        #ClientAliveCountMax 3
        #UseDNS no
        #PidFile /var/run/sshd.pid
        #MaxStartups 10:30:100
        #PermitTunnel no
        #ChrootDirectory none
        #VersionAddendum none

        # no default banner path
        #Banner none

        # override default of no subsystems
        #Subsystem	sftp	sftp-server.exe
        Subsystem    powershell c:/progra~1/powershell/7/pwsh.exe -sshs -NoLogo -NoProfile

        # Example of overriding settings on a per-user basis
        #Match User anoncvs
        #	AllowTcpForwarding no
        #	PermitTTY no
        #	ForceCommand cvs server

        Match Group administrators
        #AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys

2. After saving the changes to the sshd_config file, restart the sshd server service:

        Restart-Service sshd -PassThru

3. Placeholder

### Public Key configuration

#### Run this from the windows 10 client

1. Copy the public key from the Windows 10 client to Windows 2012 server:

    Make sure that the .ssh directory exists in your server's user home folder.

    User can either be a local or a domain account. In my case i am using a domain account

        ssh kiran@windows2012Server  new-item c:\users\kiran\.ssh -ea 0 -item directory

2. Use scp to copy the public key file generated previously on the window10 client to authorized_keys on your server

        scp C:\Users\kiran\.ssh\id_rsa.pub kiran@windows2012Server:C:\Users\kiran\.ssh\authorized_keys


3. Placeholder

### Testing SSH with SSH.exe

1. Test ssh with a domain user named kiran

        ssh -v -i  C:\Users\kiran\.ssh\id_rsa kiran@windows2012Server

    This should get you a powershell 7 console on the remote server named: windows2012Server

    You can verify using the "hostname" command.

2. If this works that means our ssh configuration is a success. we can proceed to the next step.
3. Placeholder

### Testing SSH with PowerShell : Interactive

1. Test powershell ssh-based remoting with a domain user named kiran

        Enter-PSSession -HostName windows2012Server -UserName kiran

    This should get you a powershell 7 console on the remote server named: windows2012Server

    You can verify using the "hostname" command.

2. Placeholder

### Testing with SSH with PowerShell : Non-Interactive

1. Create a ps-session

        $session = New-PSSession -HostName windows2012Server -UserName kiran

    Username parameter can be omitted if you are remoting from the client that generated the rsa key.

    However if you copied the rsa key from one client to another and use it under a different login then username needs to be specified.

2. Test with invoke-command

        Invoke-Command -Session $session -ScriptBlock { hostname }

    This should return the name of the remote computer : **windows2012Server**

3. Placeholder

>PowerShell Remoting over SSH does not currently support remote endpoint configuration and JEA (Just Enough Administration)