/**
 * matrix.js — Matrix rain background animation
 * Runs on all pages.
 */
(function () {
  const canvas = document.getElementById("matrix-canvas");
  if (!canvas) return;

  const ctx  = canvas.getContext("2d");
  const CHARS = "アイウエオカキクケコ0123456789ABCDEF<>/\\[]{}#$%@!?";

  let cols, drops, animFrame;

  function resize() {
    canvas.width  = window.innerWidth;
    canvas.height = window.innerHeight;
    cols  = Math.floor(canvas.width / 18);
    drops = Array(cols).fill(1);
  }

  function draw() {
    ctx.fillStyle = "rgba(3, 10, 14, 0.07)";
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    ctx.fillStyle = "#00ff6a1a";
    ctx.font      = "13px 'Share Tech Mono', monospace";

    for (let i = 0; i < drops.length; i++) {
      const char = CHARS[Math.floor(Math.random() * CHARS.length)];
      ctx.fillText(char, i * 18, drops[i] * 18);

      if (drops[i] * 18 > canvas.height && Math.random() > 0.975) {
        drops[i] = 0;
      }
      drops[i]++;
    }

    animFrame = requestAnimationFrame(draw);
  }

  resize();
  draw();

  window.addEventListener("resize", () => {
    cancelAnimationFrame(animFrame);
    resize();
    draw();
  });
})();
