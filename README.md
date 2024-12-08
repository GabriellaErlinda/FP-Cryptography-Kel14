# FP-Cryptography-Kel14

### Anggota
| Nama                            | NRP          |
| ------------------------------- | ------------ |
| Gabriella Erlinda Wijaya        | `5027221018` |
| Nicholas Marco Weinandra        | `5027221042` |

### Implementasi CSPRNG Berbasis Chaos
Di sini kami mengimplementasikan 2 formula CSPRNG berbasis chaos, yaitu:
1. Hybrid Chaotic (kombinasi Logistic Map, Tent Map, dan fungsi sinus)
2. RCTM (modifikasi Chaotic Tent Map dengan operasi skala dan modulo)

Algoritma enkripsi dan dekripsi yang kami gunakan adalah AES yang nantinya digunakan untuk mengenkripsi informasi kartu kredit yang digunakan untuk transaksi dalam sebuah platform e-commerce.
Kedua formula CSPRNG akan digunakan untuk men-generate key yang akan digunakan untuk mengenkripsi.

### Halaman Web
1. Dashboard
![image](https://github.com/user-attachments/assets/68928b9a-194f-4d63-91bf-ad1bffae5a7e)
Pada page `/`, user bisa menambahkan produk yang diinginkan ke dalam keranjang belanja, dan keranjang belanja akan otomatis di-update

3. Cart
![Screenshot 2024-12-01 233002](https://github.com/user-attachments/assets/85d60046-fec2-4e3f-9c13-50d45609b575)
Pada page `/cart`, user bisa melihat keranjang belanja berisi produk yang sudah dipilih, user bisa memilih untuk kembali melihat halaman katalog, atau melanjutkan ke proses checkout

5. Checkout
![Screenshot 2024-12-01 233034](https://github.com/user-attachments/assets/59ca69ba-70af-44e4-a476-f19af368cb73)
Pada page `/checkout`, user akan diminta mengisi informasi pribadi dan kartu kredit yang akan digunakan untuk pembayaran. Di akhir form, user diminta memilih metode enkripsi antara `Hybrid Chaotic` atau `RCTM`
Setelah user meng-klik tombol `Submit Payment` maka riwayat transaksi akan ditampilkan pada tabel berisi data yang telah dienkripsi, lalu performa seperti `Encryption Time (s), Decryption Time (s), Total Execution Time (s), Encryption Memory (KB), Decryption Memory (KB), Encryption Throughput (KB/sec), Encrypted Entropy` seperti pada gambar di bawah ini
![Screenshot 2024-12-02 014328](https://github.com/user-attachments/assets/27940784-956b-4c56-871f-f0ae9fd610d6)
	
7. Performance
![WhatsApp Image 2024-12-08 at 19 29 43_81844b95](https://github.com/user-attachments/assets/74ea26d0-06e7-42c1-a4ce-b3bd661b3bb7)
Dari log riwayat transaksi pada page checkout, data-data tadi akan diteruskan ke page `/performance` untuk dianalisis hasilnya

### Percobaan
Percobaan untuk menganalisis hasil perbandingan performa keduanya kami lakukan sebanyak 50x running untuk masing-masing formula.
Hasil percobaan dapat dilihat di ![Sheets Performance Analysis - Kel14](https://docs.google.com/spreadsheets/d/1wF3TNwW2jKv0-xbTv-Et2CC9iT_aiEc_6NKauzH1Ofk/edit?usp=sharing)

### Hasil Perbandingan
| TABEL PERBANDINGAN                | HYBRID CHAOTIC  | RCTM            | 
| --------------------------------- | --------------- | --------------- |
| Encryption Time (s)               |    0.00002128   |    0.00001354   |
| Decryption Time (s)               |    0.00001064   |    0.00000618   |
| Total Execution Time (s)          |    0.00005894   |    0.00004774   |
| Encryption Memory (KB)            |       0.14      |       0.14      |
| Decryption Memory (KB)            |       0.14      |       0.14      |
| Encryption Throughput (KB/sec)    |    1121.2074    |    1258.2474    |
| Encrypted Entropy                 |    3.9440564    |       3.95      |

##### **biru = hybrid chaotic, merah = rctm**
#### Encryption Time
![image](https://github.com/user-attachments/assets/88596af7-0f6d-458b-a4bd-bc4fc821adb1)

#### Decryption Time
![image](https://github.com/user-attachments/assets/1340134f-61da-4127-98b3-1a6d898ce3b6)

#### Total Execution Time
![image](https://github.com/user-attachments/assets/e9495209-16da-4250-b48b-c6d6a4cfae01)

#### Encryption Throughput
![image](https://github.com/user-attachments/assets/13556c44-abeb-4315-b3b8-a5b15027282e)

#### Encrypted Entropy
![image](https://github.com/user-attachments/assets/55b4805d-dcbd-4bf0-ae79-9c7de80eb8b8)


### Kesimpulan
Dari hasil perbandingan di atas, dapat disimpulkan bahwa kompleksitas chaos formula `hybrid chaotic` lebih tinggi karena menggabungkan 2 chaos map (logistic map dan tent map). Karena itu juga, `hybrid chaotic` juga memakan waktu proses enkripsi dan dekripsi yang lebih lama juga dibandingkan `rctm`
