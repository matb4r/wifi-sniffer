# Analizator komunikacji sieci bezprzewodowych IEEE 802.11/Wi-Fi.
Program zbiera ramki IEEE 802.11 i odpowiednio je interpretując, drukuje na wyjściu standardowym.

### Kompilacja:
```
gcc ./wifisniffer.c -o ./wifisniffer -lpcap
```
### Użycie:

```
sudo ./wifisniffer INTERFACE
```
