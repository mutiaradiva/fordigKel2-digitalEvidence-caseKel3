# Write-Up Digital Evidence Kelompok 3: Nusa Meridian Disaster

**Skenario Kasus:**
Tim *Incident Response* menerima laporan mengenai sebuah *flashdisk* (USB) mencurigakan yang dicolokkan ke *workstation* perusahaan Nusa Meridian. Laporan ini menguraikan langkah-langkah investigasi forensik untuk mengidentifikasi sampel *malware*, memahami perilakunya, dan memulihkan *flag* yang disembunyikan.

---

### Tahap 1: Akuisisi Barang Bukti (FTK Imager)

Untuk menjaga integritas barang bukti agar tidak rusak atau berubah secara tidak sengaja, investigasi tidak dilakukan langsung pada *flashdisk* fisik. Langkah pertama yang dilakukan adalah melakukan akuisisi data menggunakan **FTK Imager**.

Seluruh isi *flashdisk* disalin menjadi *forensic image* dengan format **.E01** (Expert Witness Format). Proses ini juga secara otomatis menghasilkan nilai *hash* (MD5 dan SHA1) untuk memastikan bahwa file *image* yang akan kita analisis identik 100% dengan isi *flashdisk* aslinya.

### Tahap 2: Eksplorasi & Identifikasi Sampel (Autopsy)

Setelah *file image* `.E01` berhasil dibuat, langkah selanjutnya adalah memuatnya ke dalam aplikasi forensik **Autopsy** untuk membedah struktur sistem filenya (Win95 FAT32).

Pada tahap awal eksplorasi, sempat terjadi kendala teknis di mana daftar file tidak muncul di layar. Hal ini berhasil diatasi dengan melakukan pengaturan ulang tata letak (*Window > Reset Windows*) agar panel *Result Viewer* kembali tampil.

Fokus penelusuran diarahkan pada *root directory* dari partisi utama (`vol2`). Di lokasi inilah ditemukan sampel *malware* utama yang dieksekusi saat USB dicolokkan:

<img width="844" height="438" alt="image" src="https://github.com/user-attachments/assets/2507942f-7994-4406-bb63-90f1b4334c0e" />

* **Nama File:** `combined_v2_gui.exe`
* **Status:** *Allocated* (File masih utuh)
* **Ukuran:** 394.752 bytes
* **Hash MD5:** 3fc8629856beb346c9be90f97526a392

Selain sampel utama, fitur pemulihan Autopsy juga mendeteksi jejak file yang sudah dihapus (*unallocated*) di lokasi yang sama, seperti file kompilasi `combined_v2.exe.part` dan alat bantu `write_flag.exe`.

### Tahap 3: Investigasi Pola Teks (Analisis Base64)

Sesuai dengan petunjuk dari laporan awal CISO, terdapat gambar tangkapan layar percakapan bernama `little_courrier_chat.png`. Pada pukul 09:15, dikirimkan sebuah pola teks mencurigakan berformat Base64:

`SGVsbG8gdGhlcmUsaW0gdGhlIGRldmVsb3BlciBvZiBjdXN0b20gdGhp cyBtYWxkZXYsdGhpcyBtYWx3YXJlIGlzIG5vdCBmb3IgaGFybWluZyxi dXQgZm9yIHRyYWluaW5n ICYgbGVhcm4sbGVhZCB0byBDUlRFICYgUEVO MjAwIFJlZCBUZWFtZXIsaWRlbnRpdHkgc2hpZnRpbmd~ IG0wMG5zcG VjdHJlLg==`

Setelah dilakukan proses *decoding*, teks tersebut terjemahkan menjadi:

> *"Hello there,im the developer of custom this maldev,this malware is not for harming,but for training & learn,lead to CRTE & PEN200 Red Teamer,identity shifting~ m00nspectre."*

**Temuan:** Bukti ini mengonfirmasi bahwa insiden ini merupakan bagian dari simulasi pelatihan *Red Team* untuk sertifikasi keamanan (CRTE/PEN200). Program ini dikembangkan secara kustom oleh pihak dengan alias **m00nspectre**.

### Tahap 4: Analisis Perilaku Malware

Melalui penelusuran artefak yang tersimpan di dalam *flashdisk*, perilaku operasional *malware* dapat direkonstruksi:

1. **Pengumpulan Data:** *Malware* menargetkan informasi kredensial yang tersimpan di dalam sistem, terutama data peramban web (seperti `Login Data` dan `Local State` dari Microsoft Edge).
2. **Local Staging:** Data yang berhasil dicuri tidak langsung dikirim melalui internet, melainkan ditampung ke dalam folder dengan format `information_YYYYMMDD_HHMMSS`. Folder ini disembunyikan di dalam direktori `.data` dan folder *recycle bin* ala Linux, yaitu `.Trash-1000`.
3. **Anti-Forensik:** Untuk menyembunyikan jejak operasi, *malware* segera menghapus alat pembantunya (seperti `write_flag.exe`) sesaat setelah eksekusi selesai.

### Tahap 5: Ekstraksi Flag (Terminal Linux)

<img width="960" height="540" alt="image" src="https://github.com/user-attachments/assets/8f4800d7-6fa0-4569-80eb-bbd0376fe439" />

Berdasarkan log yang ditemukan, *malware* gagal menuliskan *flag* ke dalam *flashdisk* (kemungkinan tertimpa atau terjadi *error* pada `flag_obfuscated.txt`). Oleh karena itu, *flag* harus ditarik langsung dari dalam *source code* *malware* utamanya.

File `combined_v2_gui.exe` diekstrak (*Extract File*) dari Autopsy dan dipindahkan ke dalam *environment* terminal Linux (Ubuntu Multipass). Karena format pasti dari *flag* tidak diketahui sejak awal, pencarian difokuskan menggunakan parameter kurung kurawal `{ }` yang menjadi standar umum *flag* CTF.

Eksekusi perintah menggunakan *Regular Expression* (RegEx):

```bash
strings combined_v2_gui.exe | grep "{.*}"

```

### Kesimpulan & Flag

Melalui metode analisis statis (*strings extraction*) pada berkas binari, *flag* yang disisipkan secara permanen (*hardcoded*) di dalam program berhasil ditemukan tanpa perlu mengeksekusi *malware* tersebut.

**FLAG RECOVERED:**
`FORDIG{c0ngr4tul4tI0nz_d1d_y0u_f1nd_m3?_w3ll_g00d_j0b_k3l0mp0k-3_gr33t1ng5_fr0m_m00nspectre}`
