# AES 3DS ETS Kriptograafi

- Jalankan server.py

- Jalankan 2 client.py

- Login dulu. Autentikasi untuk user bisa di hardcode di protokol.py username dari index set nya waktu inisiasi class
  - command : auth [username] [password]
    - Default username(case sensitive) : password
      - stu : 1234abcd
      - sbay : 1234abcd
  

### 3DES Mode EAX

- Kirim file dari client stu
  - command : send_3des [username tujuan] [namafile] [keypharse untuk enkripsi]
    - contoh send_3des ubay tes.txt 1234567890

- Cek file masuk di client lain
  - command : my_file

- Download file dari client ubay
  - command : donwload_3des [username asal] [namafile] [keypharse untuk dekripsi]
    - contoh download_3des stu tes.txt 1234567890
  - kalau keypharse salah hasilnya bakal unreadable


  
### AES Mode CBC

- Kirim file dari client stu
  - command : send_aes [username tujuan] [namafile] [keypharse untuk enkripsi]
    - contoh send_aes ubay tes.png 1234567890

- Cek file masuk di client lain
  - command : my_file

- Download file dari client ubay
  - command : donwload_aes [username asal] [namafile] [keypharse untuk dekripsi]
    - contoh download_aes stu tes.txt 1234567890
  - kalau keypharse salah hasilnya bakal unreadable



Kalau mau liat command nya atau barang kali aku salah tulis bisa liat di client.py

Kalau benerin kodingan 3des langusung di client.py aja ada fungsinya pake postfix 3des

Kalau benerin kodingan aes langusung di dari aes.py sama di client.py

Urusan trasnfer data semua ada diprotokol
