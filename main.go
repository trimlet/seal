// Trimlet Seal: pass one confidential piece of information to someone, once.
// See docs/apps/seal.md and docs/design.md section 3d.
package main

import (
	"time"

	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"

	"github.com/trimlet/gui"
)

func main() {
	a, w := gui.NewWindow("local.trimletseal", "Trimlet Seal")
	gui.UsePalette("red") // Seal's color (red 600, gui.IconStep)
	path, err := storePath()
	var s *Store
	var access *Access
	if err == nil {
		s, err = loadStore(path)
	}
	if err == nil {
		access, err = loadAccess(accessPath(path))
	}
	if err != nil {
		msg := canvas.NewText("✘ Could not read the codes waiting: "+err.Error(), gui.Red)
		msg.TextSize = gui.TextSize
		msg.TextStyle.Monospace = true
		w.SetContent(container.NewPadded(container.NewVBox(msg)))
		gui.Run(a, w)
		return
	}

	m := newModel(s, newHTTPServer())
	m.access = access
	m.copy = func(text string) { a.Clipboard().SetContent(text) }
	m.quit = a.Quit
	var screen *gui.Screen
	m.ui = func(f func()) { screen.Do(f) }
	m.later = func(d time.Duration, f func()) { time.AfterFunc(d, func() { screen.Do(f) }) }
	screen = gui.NewScreen(a, w, m)
	// On opening, ask the server whether something is there (and tidy old keys and rows); the first
	// time, the work for the access key starts at once, in the background.
	gui.Run(a, w, func() { screen.Do(m.start) })
}
