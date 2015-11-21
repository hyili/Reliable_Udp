# Reliable_Udp
Working for Reliable Udp and Congestion Control Window


download by type in:
```
git clone https://github.com/hyili/Reliable_Udp.git
```

then you can use the library rudp.h to write your code

tsend.c and trecv.c are the example of how it works

then you can compile the example by type in:
```
make
```

if you want to test the example program, you should select or create a file named i.txt which is the file that ready to be sent

then you can open the second terminal and run:
```
./s
```

then in the first terminal you can run:
```
./c
```

then the file i.txt would send from c to s, and named as o.txt

next you can check the file if there is any difference by type in:
```
diff i.txt o.txt
```

P.S. the file size of the i.txt should be smaller then the size set in the tsend.c file
