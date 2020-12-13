# Programowanie Systemowe<br/> Debugowanie jądra - sprawozdanie<br/>Piotr Świderski śr 12:50 - 14:40

## 1. Debugowanie modułów
 **1. Moduł 1**
        
        Moduł został załadowany:
        ```
        [   298.506783] broken_module: loading out-of-tree module tains kernel.
        [   298.506896] The BROKEN module has been inserted
        ```
        Wywołana została komenda `cat /dev/broken` (operacja została zabita)

        ```
        [student@ps2017 dev]$ sudo cat /dev/broken
        Killed
        ```
        Przydatne informacje uzyskane po wywołaniu komendy `dmesg`:
        ```
        [   2398.704348] Call Trace:
        [   2398.704353] [<ffffffffffffffc07cb354>] broken_read+0x150/0x195 [broken_module]      
        ```

        ```
        [   2398.704379] RIP [<ffffffffffffffbc230653>] kfree+0x53/0x170
        ```

        Z powyższych komunikatów można wywnioskować, że problem pojawił się przy wywoływaniu funkcji kfree() w funkcji broken_read().

        Funkcja broken_read():

        ```
        ssize_t broken_read(struct file *filp, char *user_buf, size_t count,loff_t *f_pos)
        {
 	        char *mybuf = NULL;
            int mybuf_size = 100;
	        int len, err;
	        mybuf = kmalloc(mybuf_size, GFP_KERNEL);

	        if (!mybuf) {
                return -ENOMEM;
            }

	        fill_buffer(mybuf, mybuf_size);
	        len = strlen(mybuf);
	        err = copy_to_user(user_buf, mybuf, len);
	        kfree(mybuf); // było kfree(user_buf);
	        read_count++;

            if (!err && *f_pos == 0) {
                *f_pos += len;
                return len;
	        }
            return 0;
        }
        ```
  
   W miejscu oznaczonym "//" znajdował się wskaźnik na przestrzeń użytkownika, a wydaje się, że powinien być zwalniany zaalokowany wcześniej w samej funkcji bufor "mybuf".

   W module znajdowała się także nic nie robiąca funkcja `broken_write`, a najpewniej powinna służyć do zliczania zapisów do /dev/broken, więc została ona zmodyfikowana w następujący sposób:


    ssize_t broken_write(struct file *filp, const char *user_buf, size_t count,loff_t *f_pos)
    {
      	write_count++; // wcześniej tu tego nie było
        return 1;
    }


   Po wprowadzeniu modyfikacji przetestowano poprawność działania modułu:


    [root@ps2017 ~]$ echo "test" > /dev/broken
    [root@ps2017 ~]$ echo "szklanka" > /dev/broken
    [root@ps2017 ~]$ cat /dev/broken
    I've created a buffer of size: 100
    [root@ps2017 ~]$ cat /proc/broken | head -2
    BROKEN. Reads: 2, Writes: 14
    BROKEN. Reads: 2, Writes: 14


 **2. Moduł 2**
  
   Postąpiono podobnie jak poprzednio, komunikaty po wywołaniu `cat /dev/broken`:
   
       [root@ps2017 2]# cat /dev/broken
       Killed
       
   Oraz `dmesg`:
   
   ```
        [  3466.319942] BUG: unable to handle kernel NULL pointer dereference at (null)
        [  3487.771975] IP: [<fffffffffffffbc4031fd>] memcpy_orig+0x9d/0x110   
   ```
    
   Jak widać nastąpiło odwołanie do adresu null wewnątrz funkcji memcpy(). Możliwe, że przekazano do jakiejś funkcji jądra niezainicjolizowany wskaźnik.
    
   Sekcji Call Trace:
   ```
        [  3487.772163] Call Trace:
        [  3487.772172] [<fffffffffffffbc400f5b>] ? vsnprintf+-xeb/0x500
        [  3487.772214] [<fffffffffffffbc401506>] sprintf+0x56/0x70
        [  3487.772220] [<fffffffffffffbc22fbf9>] ? kmem_cache_alloc_trace+0x159/0x1b0
        [  3487.772223] [<fffffffffffffbc07c6225] fill_buffer+0x1e/0x30 [broken_module]
        [  3487.772227] [<fffffffffffffbc258db7>] broken_read+0x45/0xe20 [broken_module] 
   ```
   Na stosie wywołań widać funkcje `fill_buffer()` oraz `broken_read()`. Najpewniej gdzieś tutaj znajduje się błąd.
   
   Funkcja `fill_buffer()`:
   ```
   int fill_buffer(char *buf, int buf_size)
   {
        sprintf(buf, "I've created a buffer of size: %d\n", buf_size);
        return strlen(buf); // było strlen(mybuf) który nie był ani przekazywany ani inicjalizowany w funkcji.
   }
   ```
   
   Wyniki testowe wyglądały tak samo jak w module nr 1, który znajduje się powyżej.
   
 **3. Moduł 3**
 
   Podobnie jak w powyższych przykładach moduł został skompilowany i załadowany. Wywołana została komenda `echo 2315 > /dev/broken`, gdzie 2315 było numerem PID powłoki bashowej, czym uzyskano taki wynik:
   
   ```
   [root@ps2017 3]# echo 2315 > dev/broken
   Killed
   ```
   Ponadto wyłączony został tryb root. Użycie komendy `dmesg` dało następujące rezultaty:
   
   ```
   [   301.506783] The BROKEN module has been inserted
   [   361.625998] perf: interrupt took to long (2511 > 2500), lowering kernel.perf_event_max_sample_rate to 79000  
   [   408.976783] BUG: unable to handle kernel NULL pointer dereference ar 0000000000090b
   [   408.976997] IP: [<ffffffffa53fd19e>] strcpy+0xe/0x20
   ```
   Oraz:
   ```
   [   408.976794] Call Trace:
   [   408.976911] [<ffffffffc09fd304>] fill_buffer_with_process_name+0x34/0x50 [broken_module]
   [   408.989111] [<ffffffffc069d398>] broke_write+078/0xce0 [broken_module]
   ```
   Można z tego wywnioskować, że błąd dotyczył funkcji `strcpy()`, którą wywołała funkcja      `fill_buffer_with_process_name()`, którą wywołała funkcja `broken_write()`
   
   Funkcja `fill_buffer_with_process_name()`:
   
   ```
   void fill_buffer_with_process_name(long pid)
   {
        struct pid *selected_pid = find_get_pid(pid);
        struct task_struct *selected_proc = pid_task(selected_pid, PIDTYPE_PID);

        if (selected_proc != NULL)
                strcpy(buf1, (char *) selected_proc->comm); // było tutaj selected_proc->pid
	else
                sprintf(buf1, "The process with PID: %ld cannot be found", pid);
   }
   ```
   PID jest liczbą, a w powyższej funkcji był wykorzytywany jako wskaźnik. Docelowo w buf1 powinna się znaleźć nazwa procesu, która zajduje się w tablice comm[].
   
 Po naprawie moduł działał w następujący sposób:
 ```
    [root@ps2017 3]# echo 3860 > dev/broken
    [root@ps2017 3]# cat dev/broken
    Process name: bash
 ```
   
 **4. Moduł 4**

Podobnie jak w powyższych przykładach moduł został skompilowany i załadowany. Wywołana została komenda `echo "abcd123" > /dev/broken` uzyskano taki wynik:

```
[root@ps2017 4]# insmod broken_module.ko
[root@ps2017 4]# mknod /dev/broken c 899 0
[root@ps2017 4]# cat /dev/broken
I've recenlty read 0 numeric characters
[root@ps2017 4]# echo "abcd123" > /dev/broken
Segmentation fault
```
`Call Trace` po wywolaniu `dmesg`:

```
        [  1285.392163] Call Trace:
        [  1285.392199] [<fffffffffffffbc400f44>] broken_write+0x44/0xb0 [broken_module]
```
Można z tego wywnioskować, że problem dotyczył jakiegoś wywołania w funkcji `broken_write()`. Z racji braku lepszych  pomysłów najlepsze wydawało się przeglądanie kolejno wywoływanych funkcji i patrzenie, czy nie występują tam jakieś anomalie. Taką funkcją okazała się `count_numbers()`. Zamiast podanego w argumentach wskaźnika str używano tam wskaźnika ptr ustawionego na NULL. Należało zamienić ptr na str oraz przenieść inkrementację na dół pętli (inaczej nie była by zliczana pierwsza cyfra w napisie). 

Funkcja `int count_numbers()` po poprawie:

```
int count_numbers(char *str)
{
        int numbers = 0;

        while (*str != 0) {
                if (isdigit(*str))
                        numbers++;
                str++;
        }

        return numbers;
}
```

Test działania:

```
[root@ps2017 4]# echo "abcd123" > /dev/broken
[root@ps2017 4]# cat /dev/broken
I've recenlty read 3 numeric characters
```

## 2. GDB
 **1. `/proc/loadavg`**
 
 Przed wykonywaniem zadań skompilowane zostało jądro oraz uruchomione QEMU z sesją GDB ustawioną na `target remote :1234`.
 
 Wynik komendy `cat /proc/loadavg`:
 
 ```
 [root@localhost ~]#cat /proc/loadavg
 Killed
 ```
 Wynik komendy `dmesg`
 ```
 [   52.371269] RIP: seq_printf+0x8/0x50 RSP: ffffc90000303d00
 ```
 Można zaobserwować, że problem nastąpił przy wywoływaniu funkcji `seq_printf()`.
 
 Wobec tego w GDB ustawiono breakpoint na funkcji `seq_printf()` i wywołano funkcje ponownie
 ```
 Continuing
 Breakpoint 1, 0xfffffffffff811afb34 in seq_printf()
 (gdb) by
 #0 0xfffffffffffff811af34 in seq_printf ()
 #1 0xfffffffffffff811f912 in loadavg_proc_show ()
 #2 0x00000000000000000000 in ?? ()
 ```
 Można z tego wywnioskować, że błąd znajduje się w funkcji `load_proc_show()`:
 
 ```
 static int loadavg_proc_show(struct seq_file *m, void *v)
 {
 	unsigned long avnrun[3];
	
	get_avenrun(avnrun, FIXED_1/200, 0);
	
	seq_printf(m, "%lu.%02lu %lu.%02lu %lu.%02lu %ld/%d %d\n", // było v zamiast m
		LOAD_INT(avnrun[0]), LOAD_FRAC(avnrun[0]),
		LOAD_INT(avnrun[1]), LOAD_FRAC(avnrun[1]),
		LOAD_INT(avnrun[2]), LOAD_FRAC(avnrun[2]),
		nr_running(), nr_threads,
		task_active_pid_ns(current)->last_pid);
	return 0;
 }
 ```
 Do `seq_printf()` przekazywano wskaźnik typu void zamiast strukturęseq_file. Wynik działania komendy do naprawie:
 ```
  [root@localhost ~]#cat /proc/loadavg
  [0.68 0.19 0.06 1/64 1491
  [root@localhost ~]#
 ```
 
 **2. `proc/PID/fd`**
  Wynik działania komendy `ls /proc/self/fd` na QEMU:
  ```
  [root@localhost ~]# ls /proc/self/fd
  ?  ?  ?  ?
  ```
  
  Wynik działania komendy `ls /proc/self/fd` na innym urządzeniu:
  ```
  [student@ps2017 linux]$ ls /proc/self/fd
  0  1  2  3
  ```
  Zdaje się, że dobrym początkiem byłoby zaczęcie od funkcji wywoływanych przy listowaniu danego katalogu, np. od fukncji z pliku `~/linux/fs/readdir.c`, np. `iterate_dir()`, bo jest na samym początku. 
  ```
 (gdb) b 
Breakpoint 1 at 0xffffffff811a2d10: file fs/readdir.c, line 25.
(gdb) c
Continuing.
  ```
  Następnie spróbowano jeszcze raz wykonać `ls /proc/self/fd`
  ```
  Breakpoint 1, iterate_dir (file=0xffff88022ff63200, ctx=0xffffc90001a27ef0) at fs/readdir.c:25
  ```
  Następnie za pomocą polecenia `list` udało się dojść do wywołania funkcji `iterate_shared(file, ctx)` w strukturze f_ops:
  
  ```
  (gdb) s
50				res = file->f_op->iterate_shared(file, ctx);
  ```
 Dalej iteracja następowała po pliku fs/proc/fd.c
 ```
 (gdb) s
proc_readfd (file=0xffff88022ff63200, ctx=0xffffc90001a27ef0) at fs/proc/fd.c:272
 ```
 
 Dalej osiągnięto funkcję `proc_readfd_common()`:
 
 ```
228	static int proc_readfd_common(struct file *file, struct dir_context *ctx,
229				      instantiate_t instantiate)
230	{
231		struct task_struct *p = get_proc_task(file_inode(file));
232		struct files_struct *files;
233		unsigned int fd;
234	
235		if (!p)
236			return -ENOENT;
237	
238		if (!dir_emit_dots(file, ctx))
239			goto out;
240		files = get_files_struct(p);
241		if (!files)
242			goto out;
243	
244		rcu_read_lock();
245		for (fd = ctx->pos - 2;
(gdb) list
246		     fd < files_fdtable(files)->max_fds;
247		     fd++, ctx->pos++) {
248			char name[PROC_NUMBUF];
249			int len = 0;
250	
251			if (!fcheck_files(files, fd))
252				continue;
253			rcu_read_unlock();
254	
255			len = snprintf(name, len, "%u", fd);
256			if (!proc_fill_cache(file, ctx,
257					     name, len, instantiate, p,
258					     (void *)(unsigned long)fd))
259				goto out_fd_loop;
260			cond_resched();
261			rcu_read_lock();
262		}
263		rcu_read_unlock();
264	out_fd_loop:
265		put_files_struct(files);
266	out:
267		put_task_struct(p);
268		return 0;
269	}
 ```
 Pętla wykonuje się po kolejnych dekryptorach (więc założony został breakpoint na jej początek). Wywoływanie kroków (aż do wywołania `snprintf()`) spowodowało:
 ```
 (gdb) n
255			len = snprintf(name, len, "%u", fd);
(gdb) n
256			if (!proc_fill_cache(file, ctx,
(gdb) p name
$0 = "\000\000\000\000\000\020\377\377\377\377\377\377\377"
```
Tablica nadal zawierała pusty string pomimo zastosowania funkcji `snprintf()`. Analiza tego miejsca pozwoliła zobaczyć, że do tej funkcji przekazywana jest len, które wynosi 0, po podstawieniu za len PROC_NUMBUF funkcja wygląda następująco:
```
char name[PROC_NUMBUF];
int len = 0;

if (!fcheck_files(files, fd))
	continue;
rcu_read_unlock();

len = snprintf(name, PROC_NUMBUF, "%u", fd); //zamiast PROC_NUMBUF było len (które wynosiło 0)
```
 Po naprawie przetestowano działanie:
 ```
  [root@localhost ~]# ls /proc/self/fd
  0  1  2  3
 ```
 **3. `proc/PID/environ` brak wypisywania**

Wynik działania komendy `ls proc/self/environ`
```
[root@localhost ~]# ls /proc/self/environ
/proc/self/environ
[root@localhost ~]# cat /proc/self/environ
```
`cat` nie wykonał nic

Na innym systemie:
```
[student@ps2017 linux]$ ls /proc/self/environ
/proc/self/environ
[student@ps2017 linux]$ cat /proc/self/environ
LC_PAPER=pl_PL.UTF-8XDG_VTNR=2XDG_SESSION_ID=2HOSTNAME=ps2017LC_MONETARY=pl_PL.UTF-8SHELL=/bin/bashTERM=xterm-256colorXDG_MENU_PREFIX=gnome-VTE_VERSION=4601HISTSIZE=1000GJS_DEBUG_OUTPUT=stderrWINDOWID=25165963LC_NUMERIC=pl_PL.UTF-8GJS_DEBUG_TOPICS=JS ERROR;JS LOGUSER=studentLS_COLORS=rs=0:di=38;5;33:ln=38;5;51:mh=00:pi=40;38;5;11:so=38;5;13:do=38;5;5:bd=48;5;232;38;5;11:cd=48;5;232;38;5;3:or=48;5;232;38;5;9:mi=01;05;37;41:su=48;5;196;38;5;15:sg=48;5;11;38;5;16:ca=48;5;196;38;5;226:tw=48;5;10;38;5;16:ow=48;5;10;38;5;21:st=48;5;21;38;5;15:ex=38;5;40:*.tar=38;5;9:*.tgz=38;5;9:*.arc=38;5;9:*.arj=38;5;9:*.taz=38;5;9:*.lha=38;5;9:*.lz4=38;5;9:*.lzh=38;5;9:*.lzma=38;5;9:*.tlz=38;5;9:*.txz=38;5;9:*.tzo=38;5;9:*.t7z=38;5;9:*.zip=38;5;9:*.z=38;5;9:*.Z=38;5;9:*.dz=38;5;9:*.gz=38;5;9:*.lrz=38;5;9:*.lz=38;5;9:*.lzo=38;5;9:*.xz=38;5;9:*.bz2=38;5;9:*.bz=38;5;9:*.tbz=38;5;9:*.tbz2=38;5;9:*.tz=38;5;9:*.deb=38;5;9:*.rpm=38;5;9:*.jar=38;5;9:*.war=38;5;9:*.ear=38;5;9:*.sar=38;5;9:*.rar=38;5;9:*.alz=38;5;9:*.ace=38;5;9:*.zoo=38;5;9:*.cpio=38;5;9:*.7z=38;5;9:*.rz=38;5;9:*.cab=38;5;9:*.jpg=38;5;13:*.jpeg=38;5;13:*.gif=38;5;13:*.bmp=38;5;13:*.pbm=38;5;13:*.pgm=38;5;13:*.ppm=38;5;13:*.tga=38;5;13:*.xbm=38;5;13:*.xpm=38;5;13:*.tif=38;5;13:*.tiff=38;5;13:*.png=38;5;13:*.svg=38;5;13:*.svgz=38;5;13:*.mng=38;5;13:*.pcx=38;5;13:*.mov=38;5;13:*.mpg=38;5;13:*.mpeg=38;5;13:*.m2v=38;5;13:*.mkv=38;5;13:*.webm=38;5;13:*.ogm=38;5;13:*.mp4=38;5;13:*.m4v=38;5;13:*.mp4v=38;5;13:*.vob=38;5;13:*.qt=38;5;13:*.nuv=38;5;13:*.wmv=38;5;13:*.asf=38;5;13:*.rm=38;5;13:*.rmvb=38;5;13:*.flc=38;5;13:*.avi=38;5;13:*.fli=38;5;13:*.flv=38;5;13:*.gl=38;5;13:*.dl=38;5;13:*.xcf=38;5;13:*.xwd=38;5;13:*.yuv=38;5;13:*.cgm=38;5;13:*.emf=38;5;13:*.ogv=38;5;13:*.ogx=38;5;13:*.aac=38;5;45:*.au=38;5;45:*.flac=38;5;45:*.m4a=38;5;45:*.mid=38;5;45:*.midi=38;5;45:*.mka=38;5;45:*.mp3=38;5;45:*.mpc=38;5;45:*.ogg=38;5;45:*.ra=38;5;45:*.wav=38;5;45:*.oga=38;5;45:*.opus=38;5;45:*.spx=38;5;45:*.xspf=38;5;45:SSH_AUTH_SOCK=/run/user/1000/keyring/sshSESSION_MANAGER=local/unix:@/tmp/.ICE-unix/1467,unix/unix:/tmp/.ICE-unix/1467USERNAME=studentPATH=/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/home/student/.local/bin:/home/student/binMAIL=/var/spool/mail/studentDESKTOP_SESSION=gnome-xorgQT_IM_MODULE=ibusQT_QPA_PLATFORMTHEME=qgnomeplatformXDG_SESSION_TYPE=x11PWD=/home/student/linuxXMODIFIERS=@im=ibusLANG=en_GB.UTF-8MODULEPATH=/etc/scl/modulefiles:/etc/scl/modulefiles:/usr/share/Modules/modulefiles:/etc/modulefiles:/usr/share/modulefilesGDM_LANG=en_GB.UTF-8LOADEDMODULES=LC_MEASUREMENT=pl_PL.UTF-8GDMSESSION=gnome-xorgHISTCONTROL=ignoredupsHOME=/home/studentSHLVL=2XDG_SEAT=seat0GNOME_DESKTOP_SESSION_ID=this-is-deprecatedXDG_SESSION_DESKTOP=gnome-xorgLOGNAME=studentXDG_DATA_DIRS=/home/student/.local/share/flatpak/exports/share/:/var/lib/flatpak/exports/share/:/usr/local/share/:/usr/share/DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/busMODULESHOME=/usr/share/ModulesLESSOPEN=||/usr/bin/lesspipe.sh %sJOURNAL_STREAM=8:29808WINDOWPATH=2XDG_RUNTIME_DIR=/run/user/1000DISPLAY=:0XDG_CURRENT_DESKTOP=GNOMELC_TIME=pl_PL.UTF-8COLORTERM=truecolorXAUTHORITY=/run/user/1000/gdm/XauthorityBASH_FUNC_module()=() {  eval `/usr/bin/modulecmd bash $*`
}BASH_FUNC_scl()=() {  local CMD=$1;
 if [ "$CMD" = "load" -o "$CMD" = "unload" ]; then
 eval "module $@";
 else
 /usr/bin/scl "$@";
 fi
}OLDPWD=/home/student_=/usr/bin/cat[student@ps2017 linux]$ 

```
Powinny zostać wypisane zmienne środowiskowe procesu. Jest możliwe, że założenie breakpointa na funkcji `vfs_read()` może doprowadzić do odnalezienia błędu. Funkcja znajduje się w pliku fs/read_write.c

```
(gdb) b vfs_read
Breakpoint 1 at 0xffffffff8118f330: file fs/read_write.c, line 461.
```
Następnie wywołano jeszcze raz komendę `cat /proc/self/environ` po czym kontynuowano aż do zatrzymania przy odczycie pliku o nazwie "environ":

```
(gdb) c
Continuing.

Breakpoint 1, vfs_read (file=0xffff88022f48e000, buf=0x7fb786265000 <error: Cannot access memory at address 0x7fb786265000>, 
    count=131072, pos=0xffffc900019e7f20) at fs/read_write.c:461
461	{
(gdb) print file->f_path.dentry->d_name
$29 = {{{hash = 2226617629, len = 7}, hash_len = 32291388701}, name = 0xffff88022f23f638 "environ"}
```
Jak widać pojawił się problem `Cannot access memory ...` przy wywoływaniu funkcji `vfs_read`
Funkcja `vfs_read()`:
```
(gdb) list vfs_read,
461	{
462		ssize_t ret;
463	
464		if (!(file->f_mode & FMODE_READ))
465			return -EBADF;
466		if (!(file->f_mode & FMODE_CAN_READ))
467			return -EINVAL;
468		if (unlikely(!access_ok(VERIFY_WRITE, buf, count)))
469			return -EFAULT;
470	
471		ret = rw_verify_area(READ, file, pos, count);
472		if (!ret) {
473			if (count > MAX_RW_COUNT)
474				count =  MAX_RW_COUNT;
475			ret = __vfs_read(file, buf, count, pos);
476			if (ret > 0) {
477				fsnotify_access(file);
478				add_rchar(current, ret);
479			}
480			inc_syscr(current);
481		}
482	
483		return ret;
484	}
```
Ustawiono zatem breakpoint na funkcję `__vfs_read()` //linijka 475. Pojawił się tam podobny problem:

```
(gdb) b __vfs_read
Breakpoint 2 at 0xffffffff8118ec30: file fs/read_write.c, line 450.
(gdb) c
Continuing.

Breakpoint 2, __vfs_read (file=0xffff88022f48e000, buf=0x7fb786265000 <error: Cannot access memory at address 0x7fb786265000>, 
    count=131072, pos=0xffffc900019e7f20) at fs/read_write.c:450
```
Przy przy ustawieniu breakpointa na funkcji `__vfs_read()` operacje zostały przeniesione do pliku `fs/proc/base.c`.
Podczas wykonywania wnętrza funkcji pojawił się problem:
```
(gdb) s
environ_read (file=0xffff88022f48e000, buf=0x7fb786265000 <error: Cannot access memory at address 0x7fb786265000>, count=131072, 
    ppos=0xffffc900019e7f20) at fs/proc/base.c:944
944		struct mm_struct *mm = file->private_data;
(gdb) list environ_read,
940	{
941		char *page;
942		unsigned long src = *ppos;
943		int ret = 0;
944		struct mm_struct *mm = file->private_data;
945		unsigned long env_start, env_end;
946	
947		/* Ensure the process spawned far enough to have an environment. */
948		if (!mm || !mm->env_end)
949			return 0;
950	
951		page = (char *)__get_free_pages(GFP_ATOMIC, 10);
952		if (!page)
953			return -ENOMEM;
954	
955		ret = 0;
956		if (!atomic_inc_not_zero(&mm->mm_users))
957			goto free;
958	
959		down_read(&mm->mmap_sem);
960		env_start = mm->env_start;
961		env_end = mm->env_start;
962		up_read(&mm->mmap_sem);
963	
964		while (count > 0) {
965			size_t this_len, max_len;
966			int retval;
967	
968			if (src >= (env_end - env_start))
969				break;
970	
971			this_len = env_end - (env_start + src);
972	
973			max_len = min_t(size_t, PAGE_SIZE, count);
974			this_len = min(max_len, this_len);
975	
976			retval = access_remote_vm(mm, (env_start + src), page, this_len, 0);
977	
978			if (retval <= 0) {
979				ret = retval;
(gdb) list
980				break;
981			}
982	
983			if (copy_to_user(buf, page, retval)) {
984				ret = -EFAULT;
985				break;
986			}
987	
988			ret += retval;
989			src += retval;
990			buf += retval;
991			count -= retval;
992		}
993		*ppos = src;
994		mmput(mm);
995	
996	free:
997		return ret;
998	}
```
Najpewniej w pętli while wykonują się właściwe operacje (tj. kopiowanie danych do przestrzeni użytkownika). Jako, że program nic nie zwraca można uznać, że pętla się nie wykonuje. W pętli 968 sprawdzany jest pewien warunek, który powoduje, że funkcja nie jest wykonywana. Spojrzenie na linijki 960 i 961 pokazuje źródło problemu. `env_start` oraz `env_end` są sobie równe. Należy zmienić `env_end = mm->env_start;` na `env_end = mm->env_end;`

Po zaaplikowaniu tej zmiany pokazały się między innymi takie dane jak HOSTNAME, TERM, SHELL, HISTSIZE.

 **3. `proc/PID/environ` problemy z częstym używaniem pliku**
 Przy probie zapisu wyniku `cat proc/self/environ` w pętli do jakieś maszyny po jamkiś czasie zaczęły pojawiać się komunikaty:
 ```
 cat: /proc/self/environL Cannot allocate memory
 ```
 
 Wynik wywołania komendy `dmesg`:
 
 ```
[ 342.724198] Call Trace:
[ 342.724690]  dump_stack+0x63/0x86
[ 342.725207]  warn_alloc+0x111/0x130
[ 2342.725726]  __alloc_pages_slowpath+0x290/0xac0
[ 342.726265]  ? proc_mem_open+0x59/0x70
[ 342.726785]  __alloc_pages_nodemask+0x18f/0x1e0
[ 342.727323]  alloc_pages_current+0x90/0x140
[ 342.727855]  __get_free_pages+0x9/0x40
[ 342.728376]  environ_read+0x55/0x1d0
 ```
 Jak widać problem pojawia się w funkcji `environ_read()` oraz w `__get_free_pages()`.
 
 W funkcji `environ_read()` znajduje się funkcja `__get_free_pages()`:
 ```
 page = (char *)__get_free_pages(GFP_ATOMIC, 10);
 ```
 Zważywszy na nazwę `page` wydawać się może, ze wystarczająca byłaby funkcja `__get_free_page()`.
 ```
 page = (char *)__get_free_page(GFP_KERNEL);
 ```
 
 Również można zauważyć, że we free nie jest zwalniana pamięć (w tym przypadku strona).
 
 ```
 free:
	free_page((unsigned long)page);
	return ret;
}
```

Po wprowadzeniu zmian, przekompilowaniu jądra i ponownym uruchomieniu QEMU wielokrotne wykonanie `cat /proc/self/environ` nie spowodowało żadnych problemów.
 
