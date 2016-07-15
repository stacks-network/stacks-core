# generated in part from 'homebrew-pypi-poet'
# to generate:
# * create a virtualenv
# * pip install homebrew-pypi-poet
# * poet -f > /path/to/brewfile

class Blockstack < Formula
  desc "Blockstack command-line client"
  homepage "https://blockstack.org"
  url "https://files.pythonhosted.org/packages/6e/f1/5518019aef7be6cb8726d1aeead954234c1afc2d6c1e2bb39725bb14ca3d/blockstack-0.0.13.6.tar.gz"
  sha256 "a665f150ed50bf51874e9f630da44ad8f12c72534c2967eb4fd51f844421b907"

  # NOTE: must be added manually, after using `poet`
  depends_on :python if MacOS.version <= :snow_leopard
  depends_on "openssl"
  depends_on "libffi"

  resource "base58" do
    url "https://files.pythonhosted.org/packages/32/8c/9b8b1b8364a945fa1ed4308d650880a5eb77bd08c2086e32e1f608440ed8/base58-0.2.3.tar.gz"
    sha256 "a691b5d194617a3de401aa2ed8818f12f1e348e95524f74a9c67246b59368fff"
  end

  resource "basicrpc" do
    url "https://files.pythonhosted.org/packages/ec/47/516aa9c118a437e833e604d3a35503cf55edcc991aba02d8505811976a57/basicrpc-0.0.2.tar.gz"
    sha256 "d471cd0a1f06766583c4b7d6cbae3ab9e2afeb64794b1cee94906cfb4da2a2af"
  end

  resource "bitcoin" do
    url "https://files.pythonhosted.org/packages/12/88/c9390638d5b2713d38ccea46c93e8ec084f052a15a94f9b1d4c66baabd24/bitcoin-1.1.42.tar.gz"
    sha256 "11ba70bd9e1c764f6bb2c4bd4c7fbebd5c9053c73f4d4325b00a98869a8b7236"
  end

  resource "bitmerchant" do
    url "https://files.pythonhosted.org/packages/a0/3c/3cc4b1f447cf0ea27c21a0e2e55adaf0064a8cd4b3294fb3c27ca27f6dd3/bitmerchant-0.1.8.tar.gz"
    sha256 "fba4c2091084ed0b4f9faac0ebbba8d255c5ccd3a18e7f877ce13aab71649ddc"
  end

  resource "blockstack-profiles" do
    url "https://files.pythonhosted.org/packages/29/13/ff709ac4a0ca5622aee4ee659eb3b214489303f10e8d065745f828510379/blockstack-profiles-0.4.4.tar.gz"
    sha256 "e18847f25bf2d264a293e1d0b5304d794e06bea92e947ca7720b08d58927883a"
  end

  resource "blockstack-storage-drivers" do
    url "https://files.pythonhosted.org/packages/12/0c/c21b3159440ca24fd7ec61c4d45776a07b32ce3aab649221f141af756a37/blockstack-storage-drivers-0.0.13.6.tar.gz"
    sha256 "ce52d795833ebb22d757734dbd76fec4b329841564c71257119436be03035df0"
  end

  resource "blockstack-utxo" do
    url "https://files.pythonhosted.org/packages/0d/b7/3a86cd1c703c4a12b09d290e5b25a566a20a34261d4aaf01134b051e8a6d/blockstack-utxo-0.0.13.0.tar.gz"
    sha256 "5c4728c3b4c450ebc00a681f570a81dfca84061d798da28594e3a4e716a4dcef"
  end

  resource "blockstack-zones" do
    url "https://files.pythonhosted.org/packages/74/8a/db5a5da42d58631568204055c90f9fc2e1790290357c4c18db369a1eb76e/blockstack-zones-0.1.6.tar.gz"
    sha256 "d2c946151e149f101e482b1afc0c8bb5d59a397a2236b7811b6d99b5e023debe"
  end

  resource "boto" do
    url "https://files.pythonhosted.org/packages/e9/74/7ef3431c37fc1f51f98cc04491cdb112dcd9f474c83b275e1a1450c24527/boto-2.41.0.tar.gz"
    sha256 "c638acdecb0a2383b517c15ac2a6ccf15a2f806aee923cc4448a59b9b73b52e0"
  end

  resource "cachetools" do
    url "https://files.pythonhosted.org/packages/ba/00/b0ec69e21142cd838b2383a7881cf18368e35847cb66f908c8f25bcbaafc/cachetools-1.1.6.tar.gz"
    sha256 "d1a44ffd2eedd138f3ba69038feb807ea54cb24e8a207a52d3a8603bc4961821"
  end

  resource "cffi" do
    url "https://files.pythonhosted.org/packages/83/3c/00b553fd05ae32f27b3637f705c413c4ce71290aa9b4c4764df694e906d9/cffi-1.7.0.tar.gz"
    sha256 "6ed5dd6afd8361f34819c68aaebf9e8fc12b5a5893f91f50c9e50c8886bb60df"
  end

  resource "commontools" do
    url "https://files.pythonhosted.org/packages/f9/f1/4ef3bdc0ee16d8cd578217f77f39f22a1cd9cb78f469d1ea8efe32b75f4b/commontools-0.1.0.tar.gz"
    sha256 "945d510c3950a693d6f7eb9328b18d3efc02bc38d1a89f28f4e9b7411fe9b0cb"
  end

  resource "cryptography" do
    url "https://files.pythonhosted.org/packages/a9/5b/a383b3a778609fe8177bd51307b5ebeee369b353550675353f46cb99c6f0/cryptography-1.4.tar.gz"
    sha256 "bb149540ed90c4b2171bf694fe6991d6331bc149ae623c8ff419324f4222d128"
  end

  resource "defusedxml" do
    url "https://files.pythonhosted.org/packages/09/3b/b1afa9649f48517d027e99413fec54f387f648c90156b3cf6451c8cd45f9/defusedxml-0.4.1.tar.gz"
    sha256 "cd551d5a518b745407635bb85116eb813818ecaf182e773c35b36239fc3f2478"
  end

  resource "ecdsa" do
    url "https://files.pythonhosted.org/packages/f9/e5/99ebb176e47f150ac115ffeda5fedb6a3dbb3c00c74a59fd84ddf12f5857/ecdsa-0.13.tar.gz"
    sha256 "64cf1ee26d1cde3c73c6d7d107f835fed7c6a2904aef9eac223d57ad800c43fa"
  end

  resource "enum34" do
    url "https://files.pythonhosted.org/packages/bf/3e/31d502c25302814a7c2f1d3959d2a3b3f78e509002ba91aea64993936876/enum34-1.1.6.tar.gz"
    sha256 "8ad8c4783bf61ded74527bffb48ed9b54166685e4230386a9ed9b1279e2df5b1"
  end

  resource "idna" do
    url "https://files.pythonhosted.org/packages/fb/84/8c27516fbaa8147acd2e431086b473c453c428e24e8fb99a1d89ce381851/idna-2.1.tar.gz"
    sha256 "ed36f281aebf3cd0797f163bb165d84c31507cedd15928b095b1675e2d04c676"
  end

  resource "ipaddress" do
    url "https://files.pythonhosted.org/packages/cd/c5/bd44885274379121507870d4abfe7ba908326cf7bfd50a48d9d6ae091c0d/ipaddress-1.0.16.tar.gz"
    sha256 "5a3182b322a706525c46282ca6f064d27a02cffbd449f9f47416f1dc96aa71b0"
  end

  resource "jsontokens" do
    url "https://files.pythonhosted.org/packages/71/fe/27f5fc1f61f881b250e65a642eb62f0ac0daddb51fddd3ecb1c85e5f0a64/jsontokens-0.0.2.tar.gz"
    sha256 "c63c3a1ddb581a4696fec28eaddb755648144058d8fb369f72db8305de204e46"
  end

  resource "keychain" do
    url "https://files.pythonhosted.org/packages/a8/25/afa689ea2ca8254b52b0d3e5b4f35736bea6cba105d5c394eecf380b50de/keychain-0.1.4.1.tar.gz"
    sha256 "e3087ec79f46d8fb618c0d2dda7e474aaf36d98b08dcc3c2375ca8db95227bcd"
  end

  resource "keylib" do
    url "https://files.pythonhosted.org/packages/e0/8e/aac128d5facaac09109f147aaf02d77a6a0617a7724456264d9250723990/keylib-0.0.5.tar.gz"
    sha256 "e52878439862f8da9add6547d3fb81f7f9ecf0bb3012799738b98194dbe8862e"
  end

  resource "mixpanel" do
    url "https://files.pythonhosted.org/packages/3b/32/ab8eae3015cb3cb1285d128854357c579e4f6c6e5df174704f750f258e7a/mixpanel-4.3.1.tar.gz"
    sha256 "5647dc18ef2a34daae56bc8838bf1f72d0be184fc4bdc0dba6e4c8d00519aa22"
  end

  resource "protocoin" do
    url "https://files.pythonhosted.org/packages/74/ac/18e6c67061166c42cf16381894b6b4f47a993b979fbeaff2f537d723dd55/protocoin-0.2.tar.gz"
    sha256 "616aeeb7a7f63a5f4a066cd4019788a4a327d80bd6fc59ce4a3c84222733eb0f"
  end

  resource "pyasn1" do
    url "https://files.pythonhosted.org/packages/f7/83/377e3dd2e95f9020dbd0dfd3c47aaa7deebe3c68d3857a4e51917146ae8b/pyasn1-0.1.9.tar.gz"
    sha256 "853cacd96d1f701ddd67aa03ecc05f51890135b7262e922710112f12a2ed2a7f"
  end

  resource "pybitcoin" do
    url "https://files.pythonhosted.org/packages/67/78/d538af65c51032f5b06377baa9713b61e798fe04b96dce6386ca6391a02f/pybitcoin-0.9.9.tar.gz"
    sha256 "0348d65232d5299d8619f2e9a0b993a72b2ee3492a71612f61d490b754421371"
  end

  resource "pycparser" do
    url "https://files.pythonhosted.org/packages/6d/31/666614af3db0acf377876d48688c5d334b6e493b96d21aa7d332169bee50/pycparser-2.14.tar.gz"
    sha256 "7959b4a74abdc27b312fed1c21e6caf9309ce0b29ea86b591fd2e99ecdf27f73"
  end

  resource "pycrypto" do
    url "https://files.pythonhosted.org/packages/60/db/645aa9af249f059cc3a368b118de33889219e0362141e75d4eaf6f80f163/pycrypto-2.6.1.tar.gz"
    sha256 "f2ce1e989b272cfcb677616763e0a2e7ec659effa67a88aa92b3a65528f60a3c"
  end

  resource "python-bitcoinrpc" do
    url "https://files.pythonhosted.org/packages/2b/bd/54ce6bb445330df0938a91bc2bcac472142a5c57e3e0b329958992a352c4/python-bitcoinrpc-0.1.tar.gz"
    sha256 "6306ab38bb73d7399f2a037c53e2f63f4445ba336f85a8e4055f005f3bf3a97f"
  end

  resource "requests" do
    url "https://files.pythonhosted.org/packages/49/6f/183063f01aae1e025cf0130772b55848750a2f3a89bfa11b385b35d7329d/requests-2.10.0.tar.gz"
    sha256 "63f1815788157130cee16a933b2ee184038e975f0017306d723ac326b5525b54"
  end

  resource "six" do
    url "https://files.pythonhosted.org/packages/b3/b2/238e2590826bfdd113244a40d9d3eb26918bd798fc187e2360a8367068db/six-1.10.0.tar.gz"
    sha256 "105f8d68616f8248e24bf0e9372ef04d3cc10104f1980f54d57b2ce73a5ad56a"
  end

  resource "utilitybelt" do
    url "https://files.pythonhosted.org/packages/ab/31/343ef1df18ffe822f02b4ca879d1f406275d3187040ac724bcf9158e4669/utilitybelt-0.2.6.tar.gz"
    sha256 "dafdb6a2dbb32e71d67a9cd35afd7c2e4993ec094e7ddb547df4cf46788770a4"
  end

  resource "virtualchain" do
    url "https://files.pythonhosted.org/packages/19/31/4130ce07b22d43e8b9412459175ff949be037a6c9d64236bee7a00a013bb/virtualchain-0.0.13.2.tar.gz"
    sha256 "bf74c4d5ff9d3d6509fc0c222e15915ca34b4d0a8fde393af2c0c8e04e1268ac"
  end

  def install
    ENV.prepend_create_path "PYTHONPATH", libexec/"vendor/lib/python2.7/site-packages"

    # NOTE: this extra path must be added manually, in order for cryptography to work (since it uses pkg_resources, which must be the one *brew* installed, not the OS X one (which is out of date))
    ENV.prepend_create_path "PYTHONPATH", "/usr/local/lib/python2.7/site-packages"

    %w[base58 basicrpc bitcoin bitmerchant blockstack-profiles blockstack-storage-drivers blockstack-utxo blockstack-zones boto cachetools cffi commontools cryptography defusedxml ecdsa enum34 idna ipaddress jsontokens keychain keylib mixpanel protocoin pyasn1 pybitcoin pycparser pycrypto python-bitcoinrpc requests six utilitybelt virtualchain].each do |r|
      resource(r).stage do
        system "python", *Language::Python.setup_install_args(libexec/"vendor")
      end
    end

    ENV.prepend_create_path "PYTHONPATH", libexec/"lib/python2.7/site-packages"
    system "python", *Language::Python.setup_install_args(libexec)

    bin.install Dir[libexec/"bin/*"]
    bin.env_script_all_files(libexec/"bin", :PYTHONPATH => ENV["PYTHONPATH"])
  end

  test do
    false
  end
end

