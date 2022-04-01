# AES 3DS ETS Kriptograafi

- Jalankan server.py

- Jalankan 2 client.py

- Login dahulu. Autentikasi untuk user bisa di temukan di protokol.py. Username didapat dari index set user pada waktu inisisasi kelas.
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
  - Jika keypharse salah hasilnya tetap terdownload namun kemungkinan besar menjadi unreadable file.
