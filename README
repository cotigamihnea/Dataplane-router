# Implementare Router

## Funcționalități

1. **Gestionarea Tabelei de Rutare**:
   - Utilizează o structură de tip trie pentru potrivirea eficientă a celui mai lung prefix.
   - Permite inserarea și căutarea rutelor în tabelă.

2. **Gestionarea ARP**:
   - Procesează cererile și răspunsurile ARP.
   - Menține un cache ARP pentru maparea adreselor IP la adrese MAC.
   - Trimite cereri ARP atunci când este necesar.

3. **Suport ICMP**:
   - Răspunde la cererile ICMP Echo.
   - Trimite mesaje de eroare ICMP (destinație inaccesibilă, timp expirat).

4. **Redirecționarea Pachetelor**:
   - Redirecționează pachetele IP către următorul hop pe baza tabelei de rutare și a cache-ului ARP.

---

### 1. **Gestionarea tabelei de rutare**
- **`insert_route`**: Inserează o rută în trie pe baza prefixului și a măștii. Prefixul și masca sunt convertite în format host (folosind `ntohl`), iar lungimea prefixului este calculată pe baza numărului de biți setați în mască (`__builtin_popcount`). Trie-ul este parcurs bit cu bit, iar dacă un nod copil nu există, este alocat dinamic. La final, ruta este stocată în nodul corespunzător.

- **`get_best_route`**: Găsește cea mai bună rută pentru o adresă IP destinație utilizând trie-ul. Adresa IP este convertită în format host, iar trie-ul este parcurs bit cu bit. Se păstrează ultima rută validă întâlnită, iar căutarea continuă până când nu mai există noduri copil. Această metodă asigură potrivirea celui mai lung prefix.

### 2. **Gestionarea ICMP**
- **`send_icmp_error`**: Funcția trimite un mesaj de eroare ICMP (destinație inaccesibilă sau timp expirat), care include antetul IP original și primii 8 octeți din pachetul original. 

- **`send_icmp_echo_reply`**: Funcția răspunde la o cerere ICMP Echo. Tipul mesajului ICMP este schimbat la `ICMP_ECHOREPLY`, iar checksum-ul este recalculat. 

### 3. **Gestionarea ARP**
- **`send_arp_request`**: Funcția trimite o cerere ARP pentru a găsi adresa MAC a următorului hop. Se construiește un pachet ARP cu antet Ethernet, unde adresa MAC destinație este setată la broadcast. Antetul ARP include informațiile despre adresa MAC și IP sursă. 

- **`handle_arp_request`**: Funcția răspunde la o cerere ARP dacă IP-ul țintă corespunde unei interfețe a routerului și se creează un pachet ARP de răspuns. 

- **`handle_arp_reply`**: Funcția procesează un răspuns ARP și actualizează cache-ul ARP. Dacă adresa IP sursă din răspuns nu există deja în cache, aceasta este adăugată împreună cu adresa MAC corespunzătoare. De asemenea, pachetele din coada de așteptare care depind de această adresă MAC sunt procesate și trimise.

### 4. **Logica redirecționării pachetelor**
- Verifică checksum-ul pachetului IP pentru a detecta eventuale erori; dacă checksum-ul nu este valid, pachetul este ignorat.
- Găsește cea mai bună rută pentru pachet utilizând funcția `get_best_route`. Dacă nu există o rută validă, se trimite un mesaj ICMP `Destination Unreachable`.
- Scade TTL-ul pachetului. Dacă TTL-ul ajunge la 0, se trimite un mesaj ICMP `Time Exceeded`.
- Dacă adresa MAC a următorului hop nu este cunoscută, se trimite o cerere ARP și pachetul este pus în coadă pentru a fi procesat ulterior.
- Dacă adresa MAC este cunoscută, antetul Ethernet este actualizat cu adresele MAC sursă și destinație corespunzătoare, iar pachetul este trimis către următorul hop.

