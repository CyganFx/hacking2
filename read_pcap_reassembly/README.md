# Дано

Есть pcap файл, который содержит 1 http запрос на http сайт(не https).

## Задача

Прочитать pcap файл и записать request и response в соответсвующие файлы, используя пакет reassembly.

# Benchmark Results

Using ZeroCopyReadPacketData:

     702           5004590 ns/op         2821661 B/op        263 allocs/op

PASS

Using for packet := range packets:

     690           5086093 ns/op         2850142 B/op        304 allocs/op

PASS

### P.S

request.txt и response.txt уже содержат данные записи которая выводит программа. Перед запуском нужно стереть данные с
файлов

