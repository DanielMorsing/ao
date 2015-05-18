/*
ao is an acme program for querying the go oracle tool. When run, ao will start
a new window with a menu of queries to be run on the invoking window. A query
can be executed by using the middle button. ao will then use the selection
as an argument to the oracle tool.

If ao is run without arguments, the file of the invoking window will be used
as scope. If an ao instance is already running, it will be switched to the
new invoking window. An ao instance will exit once its window has been closed.
*/
package main

import (
	"bufio"
	"flag"
	"fmt"
	"go/build"
	"os"
	"strconv"
	"strings"

	"9fans.net/go/acme"
	"9fans.net/go/plan9"
	"9fans.net/go/plan9/client"

	"golang.org/x/tools/oracle"
)

func fatalln(x ...interface{}) {
	fmt.Fprintln(os.Stderr, x...)
	os.Exit(1)
}

func main() {
	flag.Parse()
	// initial window
	winid := os.Getenv("winid")
	if winid == "" {
		fatalln("ao run outside acme window")
	}

	scope := getScope(flag.Args(), winid)

	win, err := acme.New()
	if err != nil {
		fatalln("Cannot create acme window: ", err)
	}
	win.Name("/ao/%s", scope[0])
	writeModes(win, winid)
	win.Ctl("clean")
	dr := dataReader{win}

	for {
		var mode string
		e, err := win.ReadEvent()
		if err != nil {
			os.Exit(0)
		}
		if e.C1 == 'M' && e.C2 == 'X' {
			// middle click on one of the modes, query the oracle
			mode = string(e.Text)
			win.Addr(",")
			win.Write("data", []byte("querying oracle\n"))
			fname, b0, b1 := getPositionInfo(winid)
			posStr := fmt.Sprintf("%s:#%d,#%d", fname, b0, b1)

			query := &oracle.Query{
				Mode:  mode,
				Pos:   posStr,
				Scope: scope,
				Build: &build.Default,
			}
			err := oracle.Run(query)
			if err != nil {
				writeModes(win, winid)
				fmt.Fprintln(dr, "Cannot query oracle: ", err)
				win.Ctl("clean")
				continue
			}
			writeModes(win, winid)
			query.WriteTo(dr)
			win.Ctl("clean")
		} else if e.Flag&1 != 0 {
			win.WriteEvent(e)
			if e.Flag&4 != 0 {
				// loaded a file, change windows
				str := winidFromFilename(string(e.Text))
				if str == "" {
					panic("could not get window from index")
				}
				winid = str
				changeName(win, winid)
				win.Ctl("clean")
			}
		}
	}
}

var mntpoint *client.Fsys

func winidFromFilename(file string) string {
	// strip address from filename
	i := strings.IndexRune(file, ':')
	if i != -1 {
		file = file[:i]
	}
	if mntpoint == nil {
		var err error
		mntpoint, err = client.MountService("acme")
		if err != nil {
			panic(err)
		}
	}
	fs, err := mntpoint.Open("index", plan9.OREAD)
	if err != nil {
		panic(err)
	}
	defer fs.Close()
	sc := bufio.NewScanner(fs)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		fi := f[5]
		if fi == file {
			return f[0]
		}
	}
	return ""
}

func getScope(arg []string, winid string) []string {
	if len(arg) == 0 {
		arg = []string{"."}
	}
	scope := make([]string, len(arg))
	for i, s := range arg {
		var scp string
		scp = s
		if s == "." {
			fname, _, _ := getPositionInfo(winid)
			scp = fname
		}
		scope[i] = scp
	}
	return scope
}

func getPositionInfo(idstr string) (name string, b0 int, b1 int) {
	id, err := strconv.ParseInt(idstr, 10, 0)
	if err != nil {
		panic("non-numerical winid" + err.Error() + idstr)
	}
	win, err := acme.Open(int(id), nil)
	if err != nil {
		fatalln("Cannot open acme window: ", err)
	}
	defer win.CloseFiles()
	name = getFilename(win)
	if isDirty(win) {
		fatalln("window must be non-dirty to query. Save the file and try again")
	}

	// acme will initialize addr on first open, if you do addr=dot before opening the addr file
	// you'll get zeroes back. Do a dummy read to get around this.
	_, _, _ = win.ReadAddr()

	err = win.Ctl("addr=dot")
	if err != nil {
		fatalln("Cannot read acme address: ", err)
	}

	// find rune offset
	q0, q1, err := win.ReadAddr()
	if err != nil {
		fatalln("Cannot read acme address: ", err)
	}
	b0, b1 = runeToByte(win, q0, q1)
	return name, b0, b1
}

func runeToByte(win *acme.Win, q0, q1 int) (b0, b1 int) {
	// convert rune offsets to byte offsets
	err := win.Addr("0")
	if err != nil {
		fatalln("Cannot decode unicode: ", err)
	}
	dr := dataReader{win}
	br := bufio.NewReader(dr)
	b0 = 0
	for i := 0; i < q0; i++ {
		_, sz, err := br.ReadRune()
		if err != nil {
			panic("whut")
		}
		b0 += sz
	}
	b1 = b0
	for i := q0; i < q1; i++ {
		_, sz, err := br.ReadRune()
		if err != nil {
			panic("whut")
		}
		b1 += sz
	}
	return
}

func isDirty(win *acme.Win) bool {
	ctl, err := win.ReadAll("ctl")
	if err != nil {
		panic("can't read info")
	}
	f := strings.Fields(string(ctl))
	if len(f) == 0 {
		panic("can't read info")
	}
	return f[4] != "0"
}

func getFilename(win *acme.Win) string {
	// use current file scope
	s, err := win.ReadAll("tag")
	if err != nil {
		fatalln("Cannot get current file name: ", err)
	}
	f := strings.Fields(string(s))
	return f[0]
}

const modes = `
callees
callers
callstack 
peers
pointsto
whicherrs

definition
describe 
freevars 

implements 
referrers

what
`

var nameStart, nameEnd int

func writeModes(win *acme.Win, idstr string) {
	fname, _, _ := getPositionInfo(idstr)
	win.Addr(",")
	win.Fprintf("data", "Current file is: ")
	nameStart, _, _ = win.ReadAddr()
	win.Fprintf("data", "%s", fname)
	nameEnd, _, _ = win.ReadAddr()
	win.Fprintf("data", "%s", modes)
}

func changeName(win *acme.Win, idstr string) {
	fname, _, _ := getPositionInfo(idstr)
	win.Fprintf("addr", "#%d,#%d", nameStart, nameEnd)
	win.Fprintf("data", "%s", fname)
	nameEnd, _, _ = win.ReadAddr()
}

type dataReader struct {
	*acme.Win
}

func (d dataReader) Read(b []byte) (int, error) {
	return d.Win.Read("data", b)
}

func (d dataReader) Write(b []byte) (int, error) {
	return d.Win.Write("data", b)
}
