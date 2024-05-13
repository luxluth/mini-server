const iters = [
  "Welcome to the miniserver's world !",
  "Bienvenue dans le monde de miniserver !",
  "ミニスーファミの世界へようこそ ！",
];
let pos = 1;
setInterval(() => {
  text.innerText = iters[pos];
  pos++;
  if (pos == iters.length) pos = 0;
}, 3e3);
