
🔍 Steganography – Image Files

Common extensions: .png, .jpeg, .jpg, .bmp, .gif, .svg, .tiff, .webp
🟢 Beginner Tools:

    steghide – Classic tool for embedding and extracting data from .jpg and .bmp files. Simple CLI interface.

    zsteg – Great for detecting LSB steganography, especially in .png and .bmp files.

    ExifTool – Extracts and edits metadata in image files like .jpg, .png, and .tiff.

🟡 Intermediate Tools:

    stegsolve – Java-based GUI tool for analyzing image layers and color planes (good for .png, .bmp).

    pngcheck – Verifies and inspects the internal structure of PNG files for hidden data.

    StegSecret – Supports analysis and recovery from various image formats; useful for multi-layer steg detection.

🔴 Expert Tools:

    openstego – Advanced tool for data hiding with watermarking and custom embedding in various image formats.

    Stegano – Python library for hiding messages in images like .png using LSB and other techniques.

    deepsec – Uses machine learning to detect hidden patterns in images. Suitable for forensics-level detection.

🔉 Steganography – Audio Files

Common extensions: .mp3, .wav, .flac, .aac, .ogg, .aiff
🟢 Beginner Tools:

    steghide – Also supports embedding data in .wav audio files.

    DeepSound – GUI tool for hiding data in .wav and .flac files; user-friendly for Windows users.

    Audacity – Popular open-source audio editor; can help analyze waveform anomalies and spectrograms.

🟡 Intermediate Tools:

    coagula / sonic visualiser – Visualize audio spectrograms; useful for detecting spectrogram-based steg (like hidden QR codes).

    Sonic Visualiser – Used to deeply analyze audio structure and visual patterns.

    AudioStego – CLI tool for LSB embedding/extraction in .wav files.

🔴 Expert Tools:

    MP3Stego – Embeds hidden messages directly into the compression process of .mp3 files.

    steganosaurus – Python-based audio stego framework supporting reversible transformations.

    inAUDible – Advanced spectral audio steganalysis and decoding tool.

🎞️ Steganography – Video Files

Common extensions: .mp4, .avi, .mkv, .mov, .flv
🟢 Beginner Tools:

    ffmpeg – Not a stego tool per se, but essential for extracting frames or audio from video.

    VirtualDub – Can inspect and edit .avi files frame-by-frame to spot visual anomalies.

    ExifTool – Extracts metadata from video containers like .mp4 and .mov.

🟡 Intermediate Tools:

    stegvideo – Python tool to hide and retrieve data from video frames.

    FrameSteg – Encodes messages in specific video frames using subtle pixel manipulation.

    vidsteg – Embeds data into video streams, with basic error correction.

🔴 Expert Tools:

    Camouflage – Cross-platform tool to hide data in video and audio streams; command-line based.

    StegoSaur – Custom scripts used in high-level CTFs to inject/encode data into frame deltas.

    OpenCV + Python Scripts – For those writing custom steg pipelines directly manipulating pixel/video data.

📄 Steganography – Document Files

Common extensions: .pdf, .docx, .xlsx, .odt, .pptx
🟢 Beginner Tools:

    Snow – Hides messages in spaces and tabs of text files.

    StegHide (again) – Works with text-containing formats for basic embedding.

    Microsoft Word – Often used manually to hide data in formatting, macros, or behind images.

🟡 Intermediate Tools:

    PDFStego – Embeds data in unused objects of PDF files.

    Oletools – Analyzes OLE-structured files (e.g., .doc, .xls) for hidden macros or data.

    docx2txt / unzip – Used to inspect raw XML content inside .docx or .pptx archives.

🔴 Expert Tools:

    StegOffice – Hides data in Office documents using font/spacing manipulation.

    LibreOffice macros – Custom steg via embedded macro payloads or hidden objects.

    Custom zip/XML tricks – Used in high-end CTFs, hiding flags inside zipped Office file structures.

🌐 Steganography – Network/Other

Common data types: .pcap, .cap, .txt, .html, .svg, custom binary
🟢 Beginner Tools:

    Wireshark – Examine .pcap files for covert data in payloads, protocols.

    Hextool / Hex Fiend – View hex data for spotting anomalies.

    base64/hex decoders – Quick data extraction from encoded network payloads.

🟡 Intermediate Tools:

    Scapy – Python tool for crafting and analyzing network packets, including steg detection.

    XORSearch – Detects XOR-encoded content in files (common in network steg).

    netsniff-ng – Analyze and inspect deep packet-level anomalies.

🔴 Expert Tools:

    Covert_TCP – Proof-of-concept tool for hiding data in TCP headers.

    DNSExfiltrator – Data hiding in DNS requests and responses.

    ICMP Stego Tools – Hides payloads in ping packets; often custom or script-based.

🔐 Cryptography Tools for CTFs

CTFs cover a wide range of cryptographic concepts. Here's the breakdown by subcategory:
🏛️ 1. Classical Ciphers

Common formats: .txt, encoded strings in challenge files or web sources
Includes: Caesar, Vigenère, substitution ciphers, ROT13, Atbash, etc.
🟢 Beginner Tools:

    CyberChef – Swiss army knife for encodings and ciphers, drag-and-drop, beginner friendly.

    Cryptii – Web-based modular cipher tool, supports Caesar, Vigenère, Base64, Morse, etc.

    dCode – Online tool with auto-solve features for common classical ciphers.

🟡 Intermediate Tools:

    quipqiup – Auto-decrypt monoalphabetic substitution ciphers.

    CTFR – Online tool with multi-crypto support, includes pattern recognition.

    Python Scripts – Custom scripts using frequency analysis, letter mapping, etc.

🔴 Expert Tools:

    Custom Brute-forcers – Code tools to crack multi-layered or combined ciphers.

    Symmetric Block Analyzer – For crafted classical-style block puzzles.

    Polygraph – Multi-layer cipher analysis using AI/ML techniques (rare, used in finals).

🧂 2. Hash Cracking & Password Recovery

Common formats: .hash, strings in .txt, web forms, or database dumps
Includes: MD5, SHA-1, SHA-256, bcrypt, NTLM, etc.
🟢 Beginner Tools:

    CrackStation – Web-based hash lookup (great for basic hashes).

    OnlineHashCrack – Free and simple tool for cracking common hashes.

    Hash Analyzer – Identifies the type of hash from format or length.

🟡 Intermediate Tools:

    hashcat – GPU-accelerated hash cracking with rulesets and wordlists.

    John the Ripper – Versatile and scriptable password cracking tool.

    rainbowcrack – Uses precomputed rainbow tables to crack hashes.

🔴 Expert Tools:

    hashcat + custom rules + mask attack – Complex rule-based and hybrid attacks.

    John + custom wordlists + pipes – Efficient setups using Unix tools.

    Custom dictionary + mangling pipeline (Python/Bash) – Smart generation of passwords based on hints in CTFs.

🔐 3. RSA & Asymmetric Crypto

Common formats: .pem, .key, .pub, .enc, .n, .e, .c files
Includes: RSA, ECC, Diffie-Hellman, ElGamal
🟢 Beginner Tools:

    RsaCtfTool (basic use) – Automates attacks like common moduli, small primes, etc.

    CryptoHack – Online platform to practice RSA concepts in CTF format.

    Factordb – Public factorization DB, often helpful in RSA CTFs.

🟡 Intermediate Tools:

    RsaCtfTool + Sage integration – Handles slightly more advanced factorization, Wiener's, etc.

    Yafu – Integer factorization tool used with RSA cracking.

    PyCrypto/PyCryptodome – Python libraries for building RSA decryptors.

🔴 Expert Tools:

    SageMath – Used for algebraic RSA vulnerabilities (partial key leaks, Coppersmith’s attack, etc.).

    z3 SMT Solver – Logic solver for symbolic expressions used in RSA variants.

    Custom lattice-based attacks (Sage) – For hard-level challenges involving partial info or Coppersmith’s method.

🧮 4. Logic & Math-Based Crypto

Common formats: .py, .sage, .txt with formulas or encoded data
Includes: Modular arithmetic, finite fields, lattice problems, logic puzzles
🟢 Beginner Tools:

    CyberChef – Can handle base conversion, modular math, and encodings.

    Python scripts (modular arithmetic) – Simple mods, inverses, GCDs.

    dCode (Math tools) – Includes modular solver, inverse finder, etc.

🟡 Intermediate Tools:

    SymPy – Python library for symbolic math, useful for equation solving.

    pwntools + Python – Combo used for scripted crypto solving.

    SageMath notebooks – More advanced crypto algebra.

🔴 Expert Tools:

    z3 + Python scripting – Solves custom constraint satisfaction problems in crypto.

    SageMath (advanced usage) – Algebraic systems, finite fields, elliptic curve analysis.

    PARI/GP – Used in number theory-heavy RSA and crypto math.

📦 5. Encodings / Obfuscation Techniques

Common formats: .txt, HTML source, challenge strings
Includes: Base64, base32/58/85, hex, binary, Morse, Braille, emoji-encodings
🟢 Beginner Tools:

    CyberChef – Converts anything to anything; perfect for simple obfuscation decoding.

    Cryptii – Visual conversion between encodings like Base64, Morse, Braille.

    Basecrack – Automatic base encoding detector and decoder.

🟡 Intermediate Tools:

    Burp Decoder / Built-in Browser Dev Tools – Used for JS obfuscation decoding.

    recode / iconv / xxd – Unix CLI encoding/decoding utilities.

    jq + base64 CLI – For decoding JSON web token strings and API data.

🔴 Expert Tools:

    Stegano Libraries for Encoded Obfuscation – Decoding content hidden in visual forms.

    Custom Python decoders – When facing unknown or layered encodings.

    Regex-based encoding detection – Write regex to identify unknown formats and decode them programmatically.
🔄 Reverse Engineering Tools for CTFs

Common file types: .exe, .elf, .bin, .so, .dll, .pyc, .apk, .jar, .dex, custom bytecode, shellcode, packed binaries
Main techniques: Static analysis, dynamic analysis, debugging, decompilation, symbolic execution, unpacking, patching
🟢 Beginner Tools

Great for basic inspection and understanding binary structure or strings.

    Ghidra

        Open-source reverse engineering suite from the NSA. GUI-based with decompiler and disassembler.

        Supports .exe, .elf, .bin, .so, .dll, and more.

    IDA Free

        Free version of the legendary IDA disassembler.

        Good static analysis and control flow visualization. Limited features vs Pro.

    strings

        CLI tool to extract ASCII/Unicode strings from binaries.

        Great for finding flags, clues, or function names.

🟡 Intermediate Tools

Require basic RE knowledge; allow more in-depth interaction, debugging, and analysis.

    radare2

        Powerful CLI RE framework for disassembling, analyzing, and scripting binary files.

        Steep learning curve but very powerful.

    x64dbg

        Windows debugger with GUI.

        Useful for debugging PE executables, setting breakpoints, watching registers.

    Cutter

        GUI frontend for radare2.

        Provides visual navigation, graph view, and better usability for reverse engineering.

🔴 Expert Tools

Advanced tools for automation, symbolic execution, and binary rewriting.

    angr

        Python framework for binary analysis and symbolic execution.

        Used in automation of solving RE challenges like maze solvers, exploit dev, etc.

    Frida

        Dynamic instrumentation toolkit for injecting JavaScript into native apps.

        Ideal for analyzing mobile apps, obfuscated binaries, and runtime manipulation.

    Binary Ninja

        Premium reverse engineering platform with API support.

        Clean GUI and scripting with Python for patching, custom analysis, and plugins.

⚙️ Optional Bonus Tools (Mixed Levels):

    ltrace/strace – Trace system/library calls on Linux.

    objdump & readelf – Inspect ELF headers, segments, and sections.

    uncompyle6 – Decompile .pyc files into readable Python.

    dnSpy – Decompiler/debugger for .NET binaries.

    apktool / jadx – Decompile and analyze Android APK files.

    retdec – Online decompiler for various platforms and architectures.

    x86emu / Unicorn / Qiling – Emulation frameworks for custom analysis.

🚀 Common CTF RE Scenarios:

    Static Challenges: Analyze .exe or .elf to locate hardcoded flag or decoding logic

    Dynamic Challenges: Use gdb/x64dbg/Frida to bypass input checks or dump memory

    Mobile Reverse Engineering: Analyze Android/iOS APKs for hardcoded keys or obfuscation

    Obfuscated Binary Puzzles: Use angr or Binary Ninja to reverse control flow, loops, or encodings
🖥️ 4. Forensics Tools for CTFs
💽 Disk/Image Forensics

File types: .img, .dd, .iso, .E01, raw binary dumps
🟢 Beginner Tools

    Autopsy – GUI platform for analyzing disk images; shows files, metadata, deleted content.

    foremost – CLI tool for carving files from raw disk images using file headers.

    Scalpel – File carving tool similar to foremost with configurable rules.

🟡 Intermediate Tools

    FTK Imager – Imaging and previewing tool for forensic data capture and browsing.

    PhotoRec – Recovers deleted files from disks, SD cards, USBs; file signature-based.

    bulk_extractor – Scans disk images to extract data like email addresses, URLs, and credit card numbers.

🔴 Expert Tools

    sleuthkit – CLI suite behind Autopsy for in-depth disk and volume analysis.

    Magnet AXIOM – Commercial tool, but used in pro CTFs for deep disk analysis (if available).

    X-Ways Forensics – Advanced disk forensics suite for deep partition and file system analysis.

🧠 Memory Forensics

File types: .raw, .mem, .vmem, .lime, RAM dumps from VMs or systems
🟢 Beginner Tools

    volatility – Memory forensics framework with plugins for process, DLL, network extraction.

    Volatility GUI (VolatilityWorkBench) – A lightweight interface for volatility beginners.

    strings – Useful for pulling readable text from memory dumps to find indicators or flags.

🟡 Intermediate Tools

    Rekall – Google’s fork of volatility; performs analysis on memory snapshots with different profiles.

    Memoryze – Memory capture and analysis tool by FireEye.

    LiME – Loadable Linux Kernel Module for capturing RAM from live Linux systems.

🔴 Expert Tools

    Redline – Comprehensive memory and malware triage tool from FireEye; rich GUI with IOC scanning.

    Volatility + YARA rules – Combine plugins with custom YARA signatures for malware detection.

    AVML – Memory acquisition tool for cloud/remote Linux systems.

🗂️ Timeline & Artifact Analysis

File types: Windows event logs (.evtx), browser history, registry hives (.dat), .log, .plaso, metadata
🟢 Beginner Tools

    ExifTool – Extract metadata from images, docs, videos, useful for hidden timestamps.

    Windows Event Viewer – Built-in for viewing .evtx logs manually.

    Registry Explorer – GUI tool for parsing registry hives from Windows systems.

🟡 Intermediate Tools

    plaso/log2timeline – Converts logs, metadata, and timestamps into timeline databases.

    Browser History Capturer (NirSoft) – Extracts browsing data from Chrome/Firefox/Edge.

    MFTECmd – Parses MFT (Master File Table) entries to detect file actions/timestamps.

🔴 Expert Tools

    Timesketch – Visual timeline analysis tool to explore .plaso output.

    ShellBags Explorer – Investigates folder open/view history from registry data.

    RECmd – Registry CLI parser for automating artifact discovery.
🌐 5. Web Exploitation Tools for CTFs
🌍 HTTP/HTTPS Interception & Manual Testing

Targets: .php, .asp, .jsp, REST APIs, cookies, headers, params
🟢 Beginner Tools

    Burp Suite Community – Intercepts and modifies HTTP/HTTPS traffic; basic repeater and decoder.

    Postman – GUI for testing APIs; supports GET/POST requests, tokens, headers.

    Fiddler – Web debugging proxy to monitor and modify HTTP(S) traffic on Windows.

🟡 Intermediate Tools

    OWASP ZAP – Similar to Burp, with built-in scanners and fuzzers.

    Charles Proxy – Friendly intercepting proxy (good for mobile traffic too).

    RESTer (Browser Extension) – Lightweight API testing directly from browser.

🔴 Expert Tools

    Burp Suite Pro – Full-featured Burp with active/passive scanning, extensions, and automation.

    mitmproxy – CLI intercepting proxy for scripting and traffic manipulation.

    Tamper Chrome / Firefox DevTools – Live request editing in browser, useful for real-time manipulation.

🔐 Vulnerability Testing & Fuzzing

Targets: Inputs (GET/POST params), headers, cookies, JSON data, file uploads
🟢 Beginner Tools

    Dirb – Basic directory brute-forcing tool using wordlists.

    Whois / dig / nslookup – Useful for domain recon and misconfig detection.

    Wayback Machine Viewer – View historical site content for info leaks.

🟡 Intermediate Tools

    wfuzz – Fuzz URLs, parameters, headers with custom payloads.

    sqlmap – Automated SQLi testing; dumps DBs, detects WAFs, uses tamper scripts.

    nikto – Scans for outdated server software, known files, and vulnerabilities.

🔴 Expert Tools

    Nuclei – Template-based vulnerability scanner; customizable for CTF/web vulns.

    ffuf – Fast and flexible fuzzer for directories, subdomains, and parameters.

    arjun – Parameter discovery tool; great for APIs and hidden inputs.

💉 Injection & Exploit Automation

Targets: XSS, SQLi, SSTI, LFI/RFI, command injection, HTTP smuggling
🟢 Beginner Tools

    XSS Hunter (legacy) – Tracks blind XSS payload callbacks.

    HackBar (browser addon) – Quick encoding, SQLi/XSS payload injection helper.

    RequestBin / webhook.site – Capture webhooks or data exfiltration test.

🟡 Intermediate Tools

    sqlmap (advanced usage) – Use tamper scripts, crawl sites, detect WAFs.

    XSStrike – XSS fuzzer and payload analyzer with intelligent bypassing.

    Dalfox – Modern XSS scanner focused on DOM-based and reflected XSS.

🔴 Expert Tools

    Burp extensions (e.g., Param Miner, Turbo Intruder) – Automate web exploit chains.

    Custom Python scripts with requests/httpx – Useful for chained injection payloads.

    Smuggler – HTTP request smuggling tool (for advanced web exploits).

📡 6. Binary Exploitation (Pwn) Tools for CTFs
🧩 Binary Types & Formats

Common file types: .elf, .out, .bin, .so, custom executables (Linux mostly), sometimes Windows .exe in mixed CTFs
Architectures: x86, x64, ARM, MIPS, etc.
Protections to bypass: NX, PIE, ASLR, Stack Canaries, RELRO
🟢 Beginner Tools

Useful for simple stack overflows, basic binary inspection, and intro to exploits.

    pwntools – Python library for writing and automating exploits; great for remote CTF services.

    checksec – Shows binary security protections like NX, PIE, RELRO, and canaries.

    gdb – Standard GNU Debugger for analyzing program memory, registers, and execution flow.

🟡 Intermediate Tools

Helpful when crafting ROP chains, understanding heap behavior, and debugging real-time.

    gef (GDB Enhanced Features) – Powerful plugin for GDB with heap analysis, register view, syscall tracing.

    ROPgadget – Finds useful return-oriented programming (ROP) gadgets in binaries.

    one_gadget – Locates one-shot RCE gadgets in libc (based on constraints and offsets).

🔴 Expert Tools

Used in advanced scenarios like heap exploitation, symbolic analysis, and custom environments.

    angr – Python framework for symbolic execution and binary analysis; automate path finding and exploit crafting.

    QEMU + GDB – Run and debug binaries compiled for different architectures via emulation (e.g., ARM/MIPS).

    Qiling Framework – Emulates userland binaries across OS/arch; excellent for sandboxing, fuzzing, or tracing.
