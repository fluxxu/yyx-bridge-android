.global _inject_start_s
.global _inject_end_s

.data

_inject_start_s:
  call *%eax
  int $3

_inject_end_s:
.word 0

.end