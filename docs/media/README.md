# Images and animations

| Output | Source | What it shows |
|---|---|---|
| `docs/img/tour.gif` | `tour.html` | the six-step product tour at the top of the README |
| `docs/img/flow.gif`, `docs/img/flow.png` | `flow.html` | who does what, step by step (the PNG is the final frame) |
| `docs/img/allow-page-*.png` | the demo's Allow page | screenshots |

Style: Deriv brand colours (coral `#FF444F`, slate `#181C25`, white) and the Inter typeface,
in the same layout as Deriv's other open-source projects: eyebrow, two-line headline with the
second line in coral, a window mock, a coral badge and a segmented progress bar.

## Re-render

Each source page defines `DURATION` and `render(t)`, which draws the exact state at time `t`.
`capture.html` steps through it, turns each frame into an image in the browser, encodes the
GIF (one shared palette; unchanged pixels are skipped) and saves it into `docs/img/`.

```bash
python docs/media/serve.py
```

Then open in any browser:

- `http://127.0.0.1:8796/docs/media/capture.html?src=tour.html&out=tour.gif&fps=10&width=1280`
- `http://127.0.0.1:8796/docs/media/capture.html?src=flow.html&out=flow.gif&fps=8&width=1500&png=flow.png`

To watch an animation live, open `tour.html#play` or `flow.html#play`. To change the project
name shown in the header, edit `NAME` at the top of the script in both files.
