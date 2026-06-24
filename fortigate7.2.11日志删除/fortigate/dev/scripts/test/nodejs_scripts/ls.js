const fs = require('fs');
const path = require('path');

const dirPath = process.argv[2] || './';

fs.stat(dirPath, (err, stats) => {
  if (err) throw err;

  if (stats.isDirectory()) {
    fs.readdir(dirPath, (err, files) => {
      if (err) throw err;

      const statPromises = files.map(file => {
        return new Promise((resolve, reject) => {
          fs.stat(path.join(dirPath, file), (err, stats) => {
            if (err) reject(err);
            resolve(stats);
          });
        });
      });

      Promise.all(statPromises).then(stats => {
        const fileInfos = stats.map((stat, index) => {
          const mode = stat.mode;
          const type = mode & fs.constants.S_IFMT;
          const permissions = (mode & fs.constants.S_IRWXU).toString(8).slice(-3) +
            (mode & fs.constants.S_IRWXG).toString(8).slice(-3) +
            (mode & fs.constants.S_IRWXO).toString(8).slice(-3);
          const size = stat.size.toString().padStart(16);
          const mtime = stat.mtime.toDateString();
          const file = files[index];
          return `${type === fs.constants.S_IFDIR ? 'd' : '-'}${permissions} ${size} ${mtime} ${file}`;
        });

        console.log(fileInfos.join('\n'));
      }).catch(err => {
        console.error(err);
      });
    });
  } else {
    fs.stat(dirPath, (err, stats) => {
      if (err) throw err;

      const mode = stats.mode;
      const type = mode & fs.constants.S_IFMT;
      const permissions = (mode & fs.constants.S_IRWXU).toString(8).slice(-3) +
        (mode & fs.constants.S_IRWXG).toString(8).slice(-3) +
        (mode & fs.constants.S_IRWXO).toString(8).slice(-3);
      const size = stats.size.toString().padStart(16);
      const mtime = stats.mtime.toDateString();
      const file = path.basename(dirPath);
      console.log(`${type === fs.constants.S_IFDIR ? 'd' : '-'}${permissions} ${size} ${mtime} ${file}`);
    });
  }
});