package lomcommon

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/syslog"
	"math"
	"os"
	"os/exec"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var writers = make(map[syslog.Priority]*syslog.Writer)

var log_level = syslog.LOG_DEBUG

var FmtFprintf = fmt.Fprintf
var OSExit = os.Exit

func init() {

    for i := syslog.LOG_EMERG; i <= syslog.LOG_DEBUG; i++ {
        writer, err := syslog.Dial("", "", (i|syslog.LOG_LOCAL7), "")
        if err != nil {
            log.Fatal(err)
        }
        writers[i] = writer
    }

    /*
     * Samples:
     *  fmt.Fprintf(writers[syslog.LOG_WARNING], "This is a daemon warning message")
     *  fmt.Fprintf(writers[syslog.LOG_ERR], "This is a daemon ERROR message")
     *  fmt.Fprintf(writers[syslog.LOG_INFO], "This is a daemon INFO message")
     */
}

/* Return currently set log level */
func GetLogLevel() syslog.Priority {
    return log_level
}


/* Set current log level */
func SetLogLevel(lvl syslog.Priority) {
    log_level = lvl
}

func getPrefix(skip int) string {
    prefix := ""
    if _, fl, ln, ok := runtime.Caller(skip); ok {
        /*
         * sample fl = /home/localadmin/tools/go/caller/t.go 
         * get last 2 elements
         * len returns 7, counting leading slash too. l[0] is empty
         * [ () (home) (localadmin) (tools) (go) (caller) (t.go) ]
         */
        l := strings.Split(fl, "/")
        c := len(l)

        /*
         * go for 2 if you can to get immediate parent dir too.
         * Note: with leading slash first is null
         * Hence go back only if > 2, not >= 2
         */
        if c > 2 {
            c -= 1      /* go for 2 if you can. Note: with leading slash first is null */
        }
        /* prefix = caller/t.go, for the example above */
        prefix = fmt.Sprintf("%s:%d:", strings.Join(l[c-1:], "/"), ln)
    }
    return prefix
}

/*
 * Log this message for given log level, if this level <= current log level
 *
 * Input:
 *  lvl - Log level for this message
 *  s - Message string, with var args as required by format in s
 *
 * Output:
 *  None
 *
 * Return:
 *  None
 */
func LogMessageWithSkip(skip int, lvl syslog.Priority, s string, a ...interface{}) string {
    ct_lvl := GetLogLevel()
    m := fmt.Sprintf(getPrefix(skip+2)+s, a...)
    if lvl <= ct_lvl {
        FmtFprintf(writers[lvl], m)
        if ct_lvl >= syslog.LOG_DEBUG {
            /* Debug messages gets printed out to STDOUT */
            fmt.Printf(m)
            fmt.Println("")
        }
    }
    return m
}


func LogMessage(lvl syslog.Priority, s string, a ...interface{}) string {
    return LogMessageWithSkip(2, lvl, s, a...)
}


/* Log this message for panic level and exit */
func LogPanic(s string, a ...interface{}) {
    LogMessage(syslog.LOG_CRIT, s + "LoM exiting ...", a...)
    OSExit(-1)
}

var lastError error = nil

func GetLastError() error {
    return lastError
}

func ResetLastError() {
    lastError = nil
}

/* Log this message at error level */
func LogError(s string, a ...interface{}) error {
    lastError = errors.New(LogMessage(syslog.LOG_ERR, s, a...))
    return lastError
}


/* Log this message at warning level */
func LogWarning(s string, a ...interface{})  {
    LogMessage(syslog.LOG_WARNING, s, a...)
}


/* Log this message at info level */
func LogInfo(s string, a ...interface{})  {
    LogMessage(syslog.LOG_INFO, s, a...)
}


/* Log this message at debug level */
func LogDebug(s string, a ...interface{})  {
    LogMessage(syslog.LOG_DEBUG, s, a...)
}

/* Log this message at notice level */
func LogNotice(s string, a ...interface{}) {
	LogMessage(syslog.LOG_NOTICE, s, a...)
}

/**********************************************************************/
/* Log Periodic 													  */
/**********************************************************************/

var uuid_suffix = 0
var UUID_BIN = "uuidgen"

/* Helper to get UUID as string */
func GetUUID() string {
    if newUUID, err := exec.Command(UUID_BIN).Output(); err != nil {
        LogError("Internal failed uuidgen. (%s)", err)
        uuid_suffix++
        return fmt.Sprintf("%v-%d", time.Now().Unix(), uuid_suffix)
    } else {
        return string(newUUID)[:36]
    }
}


const A_DAY_IN_SECS = int64(24 * 60 * 60)

/* Info related to logging periodically */
type LogPeriodicEntry_t struct {
    ID      string          /* Identifier provided by caller */
    Message string          /* string to log */
    Lvl     syslog.Priority /* Log Level to use */
    Period  int             /* period in seconds */
    /* TODO: Change period to list of {period, cnt}
     * after finishing cnt writes, move to next entry in list.
     * Caller may send [ {5, 100}, {3600, 0} ], implying
     * Write first 100 logs for every 5 seconds. After that
     * write logs for every hour forever (cnt = 0) 
     */
}

type LogPeriodicEntryInt_t struct {
    LogPeriodicEntry_t
    Due     int64           /* Next due epoch time point */
    index   uint64          /* Add a sequential index to the message */
                            /* This can help identify repeated logs with index */
                            /* indicating set to count of logs written so far */
}

/* Log Periodic module */
type logPeriodic_t struct {
    /* Channel to communicate to logging routine */
    logCh               chan *LogPeriodicEntry_t

    logPeriodicList     map[string]*LogPeriodicEntryInt_t
    logPeriodicSorted   []*LogPeriodicEntryInt_t

    /* TODO: Any entry after logging repeatedly at set period 
     * for a day or two, reduce the period to every hour
     * No point in polluting logs, as we have screamed enough
     */
}


var logPeriodic *logPeriodic_t

/* Get Log Periodic instance */
func GetlogPeriodic() *logPeriodic_t{
    if logPeriodic != nil {
        return logPeriodic
    }    
    // TODO: Replace with global abort channel later
    chAbort := make(chan interface{})
    logPeriodicInit(chAbort)
    return logPeriodic
}

/* Initialize the singleton instance for log periodic */
func logPeriodicInit(chAbort chan interface{}) {
    logPeriodic = &logPeriodic_t {
        logCh: make( chan *LogPeriodicEntry_t),
        logPeriodicList: make(map[string]*LogPeriodicEntryInt_t),
        logPeriodicSorted: nil,
    }

    go logPeriodic.run(chAbort)
}

/* Helper to add a log periodic entry */
func (p *logPeriodic_t) AddLogPeriodic(l *LogPeriodicEntry_t) error {
    if ((len(l.ID) == 0) || (len(l.Message) == 0)) {
        return LogError("LogPeriodicEntry ID or message is empty")
    }
    min := GetConfigMgr().GetGlobalCfgInt("MIN_PERIODIC_LOG_PERIOD_SECS")
    if l.Period < min {
        return LogError("LogPeriodicEntry Period(%v) < min(%v)", l.Period, min)
    }
    p.logCh  <- l
    return nil
}

/* Helper to remove a previouslu added log periodic entry */
func (p *logPeriodic_t) DropLogPeriodic(ID string) {
    if len(ID) > 0 {
        /* Emtpy Message implies drop */
        p.logCh  <- &LogPeriodicEntry_t {ID: ID }
    }
}

func (p *logPeriodic_t) run(chAbort chan interface{}) {
    tout := A_DAY_IN_SECS           /* Just a init value; Once per day */

    for {
        upd := false
        select {
        case l := <- p.logCh:
            upd = p.update(l)

        case <- time.After(time.Duration(tout) * time.Second):
            upd = p.writeLogs()

        case <- chAbort:
            LogDebug("Terminating LogPeriodic upon explicit abort")
            return
        }

        if upd {
            sort.Slice(p.logPeriodicSorted, func(i, j int) bool {
                return p.logPeriodicSorted[i].Due < p.logPeriodicSorted[j].Due
            })
        }
        /* Recompute tout */
        if len(p.logPeriodicSorted) > 0 {
            due := p.logPeriodicSorted[0].Due
            now := time.Now().Unix()
            if now >= due {
                tout = 0
            } else {
                tout = due - now
            }
        } else {
            /* No data to print */
            tout = A_DAY_IN_SECS
        }
    }
}

func (p *logPeriodic_t) updatePeriod(id string, newPeriod int) error {
	entry, ok := logPeriodic.logPeriodicList[id]
	if !ok {
		return LogError("Periodic entry with ID(%s) not found", id)
	}
	newentry := &LogPeriodicEntry_t{
		ID:      id,
		Message: entry.Message,
		Lvl:     entry.Lvl,
		Period:  newPeriod,
	}

	return logPeriodic.AddLogPeriodic(newentry)
}

func (p *logPeriodic_t) update(l *LogPeriodicEntry_t) bool {
    upd := false
    v, ok := p.logPeriodicList[l.ID]
    if len(l.Message) > 0 {
        if !ok || ((*v).LogPeriodicEntry_t != *l) {
            p.logPeriodicList[l.ID] = &LogPeriodicEntryInt_t{*l, 0, 0} /* Set Due immediate */
            upd = true
        }
    } else if ok {
        delete (p.logPeriodicList, l.ID)
        upd = true
    }
    if upd {
        p.logPeriodicSorted = make([]*LogPeriodicEntryInt_t, len(p.logPeriodicList))

        i := 0
        for _, v := range p.logPeriodicList {
            p.logPeriodicSorted[i] = v
            i++
        }
    }
    return upd
}


func (p *logPeriodic_t) writeLogs() bool {
    now := time.Now().Unix()
    upd := false 

    for _, v := range p.logPeriodicSorted {
        if now >= v.Due {
            LogMessage(v.Lvl, "periodic:%v (%s)", v.index, v.Message)
            v.Due = now + int64(v.Period)
            v.index++
            upd = true
        } else {
            break
        }
    }

    return upd
}

/**** Log Periodic Helpers ******/

func AddPeriodicLogNotice(ID string, message string, period int) error {
	return AddPeriodicLogEntry(ID, message, syslog.LOG_NOTICE, period)
}

func AddPeriodicLogInfo(ID string, message string, period int) error {
	return AddPeriodicLogEntry(ID, message, syslog.LOG_INFO, period)
}

func AddPeriodicLogDebug(ID string, message string, period int) error {
	return AddPeriodicLogEntry(ID, message, syslog.LOG_DEBUG, period)
}

func AddPeriodicLogError(ID string, message string, period int) error {
	return AddPeriodicLogEntry(ID, message, syslog.LOG_ERR, period)
}

func AddPeriodicLogEntry(ID string, message string, lvl syslog.Priority, period int) error {
	entry := &LogPeriodicEntry_t{
		ID:      ID,
		Message: message,
		Lvl:     lvl,
		Period:  period,
	}
	err := GetlogPeriodic().AddLogPeriodic(entry)
	if err != nil {
		return err
	}
	return nil
}

func RemovePeriodicLogEntry(ID string) {
	GetlogPeriodic().DropLogPeriodic(ID)
}

func UpdatePeriodicLogTime(id string, newPeriod int) error {
	return GetlogPeriodic().updatePeriod(id, newPeriod)
}

func DurationToSeconds(tduration time.Duration) int {
	return int(tduration.Seconds())
}

/*************************************************************************************************/
/* One shot Timer 																				 */
/*************************************************************************************************/

type OneShotEntry_t struct {
    due     int64       /* Time point of firing as epoch secconds */
    msg     string      /* Just info only; Used for logging */
    f       func()      /* Function to call upon due */
    disable bool        /* == true, f will not be called, if set before due */
    done    bool        /* Set to true, upon firing / calling f */
}

/* Disable it. If disabled, before fired/done, f will not be called */
func (p *OneShotEntry_t) Disable() {
    p.disable = true
}

/* Get current status */
func (p *OneShotEntry_t) IsDisabled() bool {
    return p.disable
}

/* Get current status */
func (p *OneShotEntry_t) IsDone() bool {
    return p.done
}

type oneShotTimer_t struct {
    ch  chan *OneShotEntry_t    /* Caller reqs are sent to handler via this chan */
    initOneShotTimer bool       /* True - Upon first request, initialized */
} 

var oneShotTimer = oneShotTimer_t { make(chan *OneShotEntry_t, 1), false }

/*
 * Helper to call a function upon given time provided in seconds, just once..
 *
 * Input:
 *  tout    -   Timeout in seconds
 *
 *  msg     -   Only used for logging. During any debugging, this will
 *              this will be handy
 *
 *  f       -   Function to call. Called as a Go routine. There is no
 *              further restriction on the func implementation
 *
 *  Output:
 *      None
 *
 *  Return:
 *      An instance of OneShotEntry_t. Caller may use to disable or
 *      and/or use other methods available to get its state
 *      A disabled entity will not be called, when it becomes due.
 */
func AddOneShotTimer(tout int64, msg string, f func()) *OneShotEntry_t {
    tmr := &OneShotEntry_t{ due: time.Now().Unix() + tout, msg: msg, f: f }
    oneShotTimer.ch <- tmr
    if !oneShotTimer.initOneShotTimer {
        oneShotTimer.initOneShotTimer = true
        go oneShotTimer.runOneShotTimer()
        LogDebug("Started oneShotTimer.runOneShotTimer")
    }
    /* Caller can disable and/or get status; optional */
    return tmr
}

/*
 * Call all entries that are due.
 * Remove called/disabled. 
 * Return the next earliest due 
 */
func callback(all map[int64][]*OneShotEntry_t) int64 {
    nxt := int64(math.MaxInt64)
    if len(all) > 0 {
        tnow := time.Now().Unix()
        done := make([]int64, len(all))
        cnt := 0
        for k, l := range(all) {
            if k <= tnow {
                for _, e := range l {
                    if !e.disable {
                        e.done = true
                        go e.f()
                        LogDebug("One shot timer: (%s) fired", e.msg)
                    } else {
                        LogDebug("One shot timer: (%s) skipped as disabled", e.msg)
                    }
                }
                done[cnt] = k
                cnt++
            } else {
                drop := true
                for _, e := range l {
                    if !e.disable {
                        drop = false
                    }
                }
                if drop {
                    done[cnt] = k
                    cnt++
                } else if nxt > k { 
                    nxt = k
                }
            }
        }
        for i:=0; i<cnt; i++ {
            delete(all, done[i])
        }
    }
    return nxt
}


/*
 * Started on first request for oneshot firing.
 * Recceives requests via ch
 * Fire timer to call the due entries
 * Run forever.
 * With no requests, it just wakes up once a day.
 */
func (p *oneShotTimer_t) runOneShotTimer() {
    all := make(map[int64][]*OneShotEntry_t)

    for {
        nxt := callback(all)
        tout := A_DAY_IN_SECS
        if nxt != math.MaxInt64 {
            tout = nxt - time.Now().Unix()
            if tout < 0 {
                tout = 0
            }
        }

        select {
        case tmr := <- p.ch:
            all[tmr.due] = append(all[tmr.due], tmr)

        case <- time.After(time.Duration(tout) * time.Second):
        }
    }
}

/****************************End Oneshor timer************************************************/

/*************************************************************************************************/
/* Goroutine Tracker																			 */
/*************************************************************************************************/

/* TODO: Goutham : Add a run method which will carry a non-zero timeout. This method will block 
until either the called routine returns or timeout fires., whichever occurs earlier.
If timeout fires, it kick off periodic log message and stop the message upon the routine returns. */

/* TODO: Goutham : For WaitAll, accept a systemwide channel which will timeout the function */
 
// GoroutineTracker is a helper for tracking goroutines. It can be used to
// a) Track all goroutines
// b) wait on specific goroutine to finish
// c) Get status of all goroutines
// d) Get status of specific goroutine

type GoroutineStatus bool
const (
	GoroutineStatusRunning GoroutineStatus = false
	GoroutineStatusFinished GoroutineStatus = true
)

type Goroutine struct {
	Status    GoroutineStatus
	done      chan struct{}
	StartTime time.Time
	EndTime   time.Time
	args      interface{}
}

type GoroutineInfo struct {
    Goroutine
	Name      string
	Duration  time.Duration
}

type GoroutineTracker struct {
	mlock      sync.Mutex
	goroutines map[string]*Goroutine
	waitGroup  sync.WaitGroup
}

// Create a new GoroutineTracker and return GoroutineTracker instance
//
// Parameters:
// - None:
//
// Returns:
// - pointer to a new GoroutineTracker instance:
func NewGoroutineTracker() *GoroutineTracker {
	return &GoroutineTracker{
		mlock:      sync.Mutex{},
		goroutines: make(map[string]*Goroutine),
		waitGroup:  sync.WaitGroup{},
	}
}

// Start a goroutine with given name. If a goroutine with same name already exists, then it panics
// Returns true if the goroutine is runing, false otherwise.
//
// Parameters:
// - name: the name of the goroutine
// - fn  : Function to be called
// - args - Arguments to be passed to the function
//
// Returns:
// - None:
func (grt *GoroutineTracker) Start(name string, fn interface{}, args ...interface{}) {
	grt.mlock.Lock()
	defer grt.mlock.Unlock()

	if _, ok := grt.goroutines[name]; ok {
		// Goroutine with same name already exists & active
        if grt.goroutines[name].Status == GoroutineStatusRunning {
            panic(fmt.Sprintf("Cannot start goroutine, %q as its active", name))
        } else {
            // Goroutine with same name already exists & finished
            LogInfo("Goroutine %s is finished. Deleting it from goroutine tracker", name)
            delete(grt.goroutines, name)           
        }
	}

	g := &Goroutine{Status: GoroutineStatusRunning, done: make(chan struct{}), StartTime: time.Now(), args: args}
	grt.goroutines[name] = g
	grt.waitGroup.Add(1)

	// Start the goroutine
	go func() {
		defer func() {
			grt.mlock.Lock()
			defer grt.mlock.Unlock()

			g.Status = GoroutineStatusFinished
			g.EndTime = time.Now()
			close(g.done)
			grt.waitGroup.Done()
		}()

		// Get the reflect.Value of the function
		f := reflect.ValueOf(fn)

		// If the function is not a valid type, panic with an error message
		if f.Kind() != reflect.Func {
			panic("Invalid function type provided to Start method of GoroutineTracker instance with name " + name + "") 
		}

		// If arguments are provided, call the function with the arguments
		if len(args) > 0 {
			// Convert the arguments to a slice of reflect.Value
			argVals := make([]reflect.Value, len(args))
			for i, arg := range args {
				argVals[i] = reflect.ValueOf(arg)
			}

			// Call the function with the arguments
			f.Call(argVals)
		} else {
			// Call the function without arguments
			f.Call(nil)
		}
	}()
}

// Wait for a goroutine with given name to finish. 
// CAUTION : This may bocks on channel. So, it should be called in a separate goroutine
// Parameters:
// - name: the name of the goroutine to check
//
// Returns:
// - bool:
func (grt *GoroutineTracker) Wait(name string) {

	grt.mlock.Lock()
	g, ok := grt.goroutines[name]
	grt.mlock.Unlock()

	if ok {
		<-g.done
	}
}

// Wait for a all the goroutine to finish.
// CAUTION : This blocks as intended.
// Parameters:
// - timeout: timeout in seconds. If timeout is 0, then it waits forever
//
// Returns:
// - bool: true if all goroutines finished within timeout, false otherwise
func (grt *GoroutineTracker) WaitAll(timeout time.Duration) bool {
    c := make(chan struct{})
    go func() {
        grt.waitGroup.Wait()
        close(c)
    }()
    
    if timeout == 0 {
        <-c
        return true
    }
    
    select {
    case <-c:
        return true
    case <-time.After(timeout):
        LogInfo("WaitAll timed out after %v", timeout)
        return false
    }
}

// Checks if a goroutine with the given name is currently running or not.
// Returns true if the goroutine is running, false otherwise.
//
// Parameters:
// - name: the name of the goroutine to check
//
// Returns:
// - bool: status of goroutine
// - error: error if goroutine with given name doesn't exist
func (grt *GoroutineTracker) IsRunning(name string) (bool,error) {
	grt.mlock.Lock()
	defer grt.mlock.Unlock()

	if g, ok := grt.goroutines[name]; ok {
		return g.Status == GoroutineStatusRunning, nil
	}

	// Goroutine with given name doesn't exist
	return false, fmt.Errorf("Goroutine with name %q doesn't exist", name)
}

// Gets the start time of a goroutine with the given name. It may be runnning or completed
// Parameters:
// - name: the name of the goroutine
//
// Returns:
// - string: start time of the goroutine
// - error: error if goroutine with given name doesn't exist
func (grt *GoroutineTracker) GetTimeStarted(name string) (string, error) {
    grt.mlock.Lock()
    defer grt.mlock.Unlock()

    if g, ok := grt.goroutines[name]; ok { // if goroutine exists		
		return g.StartTime.String(), nil
    }

	// Goroutine with given name doesn't exist
	return "", fmt.Errorf("Goroutine with name %q doesn't exist", name)
}

// Returns a list of GoroutineInfo. If name is nil then return info for all the goroutines being tracked
// If name is given, then return info for that goroutine
// Parameters:
// - name: the name of the goroutine
//
// Returns:
// - []interface{}: list of GoroutineInfo
func (grt *GoroutineTracker) InfoList(name *string) []interface{} {
	grt.mlock.Lock()
	defer grt.mlock.Unlock()

    // if name is given, return info for that goroutine
	if name != nil {
		if g, ok := grt.goroutines[*name]; ok {
			info := GoroutineInfo{
				Goroutine: *g,
				Name:      *name,
				Duration:  time.Since(g.StartTime),
			}
			return []interface{}{info}
		}
		return []interface{}{}
	}

    // return info for all goroutines
	var list []interface{}
	for name, g := range grt.goroutines {
		if g == nil {
			continue
		}
		duration := time.Duration(0)
		if g.Status == GoroutineStatusRunning {
			duration = time.Since(g.StartTime)
		} else if g.Status == GoroutineStatusFinished {
			duration = g.EndTime.Sub(g.StartTime)
		}
		info := GoroutineInfo{
			Goroutine: *g,
			Name:      name,
			Duration:  duration,
		}
		list = append(list, info)
	}

	return list
}


// TODO: Goutham : Cleanup

 /***** Usage Examples

func myFunc(args ...interface{}) {
	fmt.Println("Goroutine is running with args:", args)
	time.Sleep(2 * time.Second)
}

type MyStruct struct {
	Name string
}

func (s *MyStruct) Print() {
	fmt.Println(s.Name)
}

func (s *MyStruct) PrintArg(a int, b int) {
	fmt.Printf("Testing with args .......... %d %d", a,b)
}


func main() {
	mygoroutinetracker := NewGoroutineTracker()

	// Start a goroutine
	mygoroutinetracker.Start("goroutine1", myFunc, "arg1", "arg2")

	// Check if the goroutine is still running
	if status,ok := mygoroutinetracker.IsRunning("goroutine1"); ok {
		fmt.Println("Goroutine1 is still running.")
	}

    if timeStarted,ok := mygoroutinetracker.GetTimeStarted("goroutine1"); ok {
        fmt.Println("Goroutine1 started at", timeStarted)
    }

	// Wait for the goroutine to finish
	mygoroutinetracker.Wait("goroutine1")

	// List all the goroutines and their statuses
	fmt.Println("Goroutine statuses:")
	for _, g := range mygoroutinetracker.List() {
		fmt.Println(g)
	}

	// ---------  Valid calls - Valid way of using the API
	mygoroutinetracker.Start("test", func (a int, b int) { fmt.Printf("hello... %d %d", a,b) }, 10, 20)
	mygoroutinetracker.Start("test1", func () { fmt.Printf("hello") })
	var ptr = &MyStruct{"hello"}
	mygoroutinetracker.Start("test3", ptr.Print)
	mygoroutinetracker.Start("test4", ptr.PrintArg, 10, 20)

	// ------- panic calls - Invalid way of using the API
	//mygoroutinetracker.Start("test5", func (a int, b int) { fmt.Printf("hello %d %d", a,b) })
	//mygoroutinetracker.Start("test6", func () { fmt.Printf("hello") }, 10, 20)
	//mygoroutinetracker.Start("test7", ptr.Print, 10, 20)
	//mygoroutinetracker.Start("test8", ptr.PrintArg)
}
****************************End GoRoutine Tracker************************************************/

/*************************************************************************************************/
/* Read Environment variables																	 */
/*************************************************************************************************/

// TODO: Goutham : Cleanup unnecessary ENV variables and corerct default path
// variable name , system env variable name, default value
const EnvMapDefinitionsStr = `{
    "ENV_session_id": {
        "env": "XDG_SESSION_ID",
        "default": "default_session_id"
    },
    "ENV_lom_conf_location": {
        "env": "LOM_CONF_LOCATION",
        "default": "path/to/conf"
    }
}`

// key is EnvMapDefinitionsStr keys. Value is string. If its "", then no value exists. Convert them to appropriate before usage.
// e.g. ENV_lom_conf_location -> "path/to/conf"
var envMap = map[string]string{}

func LoadEnvironmentVariables() {
	var envMapDefinitions map[string]map[string]string
	if err := json.Unmarshal([]byte(EnvMapDefinitionsStr), &envMapDefinitions); err != nil {
		return
	}
	for key, value := range envMapDefinitions {
		envVal, exists := os.LookupEnv(value["env"])
		if !exists {
			envVal = value["default"]
		}
		envMap[key] = envVal
	}
}

func GetEnvVarString(envname string) (string, bool) {
	value, exists := envMap[envname]
	return value, exists
}

func GetEnvVarInteger(envname string) (int, bool) {
	intVal, err := strconv.Atoi(envMap[envname])
	if err != nil {
		return 0, false
	}
	return intVal, true
}

func GetEnvVarFloat(envname string) (float64, bool) {
	floatVal, err := strconv.ParseFloat(envMap[envname], 64)
	if err != nil {
		return 0.0, false
	}
	return floatVal, true
}

func GetEnvVarAny(envname string) (interface{}, bool) {
	value, exists := envMap[envname]
	return value, exists
}

func GetEnvVarFromOS(key string) (string, bool) {
	value, exists := os.LookupEnv(key)
	return value, exists
}

/********************** End read Environemnt Variable ********************************/