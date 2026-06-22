
set $should_print = 0

set $saved_buf = 0

break SSL_read
commands
  silent

  set $saved_buf = (char*)$rsi
  set $should_print = 1
  finish
end

# 定义 hook-stop，程序每次停止时都会自动执行
define hook-stop
  if $should_print == 1
    set $should_print = 0
    if $eax > 0
      printf "SSL_read returned %lld bytes, data: %.64s\n", $eax, $saved_buf
	  
	  printf "hex data: \n"
	  x/64xb $saved_buf

    end
  end
end