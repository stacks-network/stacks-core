import util from 'util';

function doLog() {
  console.log(util.inspect({ asdF: 4545, ggg: { '5656': true } }));
}

doLog();

export { doLog };
