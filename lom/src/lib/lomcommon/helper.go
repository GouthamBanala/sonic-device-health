package lomcommon

import (
    "encoding/json"
    "errors"
    "fmt"
    "io"
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

/* "go test" must use "-v" option to turn on testmode */
var logSuffix = ""

var writers = make(map[syslog.Priority]io.Writer)

var log_level = syslog.LOG_DEBUG
var vendor = ""

var FmtFprintf = fmt.Fprintf
var OSExit = os.Exit

func RunPanic(m string) {
    panic(m)
}

var DoPanic = RunPanic

func init() {
    InitSyslogWriter("")
}

// To-Do : Goutham/Renuka : Make path as global const and load config from init()
func InitSyslogWriter(path string) {
    isTest := false
    if GetLoMRunMode() == LoMRunMode_Test {
        logSuffix = "\n"
        isTest = true
    }

    /* To-Do : Goutham : Config item "SYSLOG_FACILITY_LEVEL" must be defined in the globals.conf.json. If its not defined, then default
       to "LOG_LOCAL7". Also, this function must be called at engine & pluginmgr startup time. Come up in a better way to handle this. */
    level, err := GetSyslogFacilityLevelFromConfig(path)
    if err != nil {
        level = "LOG_LOCAL7"
        fmt.Println("Error getting syslog facility level. Defaulting to LOG_LOCAL7. Err : {}", err)
    }

    vendor, err = GetVendorFromConfig(path)
    if err != nil {
        fmt.Println("Error getting vendor. Defaulting to empty. Err : {}", err)
    }

    var priority syslog.Priority
    switch level {
    case "LOG_LOCAL0":
        priority = syslog.LOG_LOCAL0
    case "LOG_LOCAL1":
        priority = syslog.LOG_LOCAL1
    case "LOG_LOCAL2":
        priority = syslog.LOG_LOCAL2
    case "LOG_LOCAL3":
        priority = syslog.LOG_LOCAL3
    case "LOG_LOCAL4":
        priority = syslog.LOG_LOCAL4
    case "LOG_LOCAL5":
        priority = syslog.LOG_LOCAL5
    case "LOG_LOCAL6":
        priority = syslog.LOG_LOCAL6
    case "LOG_LOCAL7":
        priority = syslog.LOG_LOCAL7
    default:
        fmt.Println("Invalid syslog facility level:", level)
        priority = syslog.LOG_LOCAL7
    }

    for i := syslog.LOG_EMERG; i <= syslog.LOG_DEBUG; i++ {
        if !isTest {
            if w, err := syslog.Dial("", "", (i | priority), ""); err != nil {
                fmt.Fprintf(os.Stderr, "Failed to get syslog writer. Exiting ...\n")
                OSExit(-1)
            } else {
                writers[i] = w
            }
        } else {
            writers[i] = os.Stderr
        }
    }
}

/* Return currently set log level */
func GetLogLevel() syslog.Priority {
    return log_level
}

/* Set current log level */
func SetLogLevel(lvl syslog.Priority) {
    log_level = lvl
}

/* setprefix is used to set a prefix for all log messages */
var apprefix string

func SetPrefix(p string) {
    if len(p) > 0 {
        apprefix = p
        if vendor != "Arista" {
            apprefix += ": "
        }
    } else {
        apprefix = ""
        if vendor == "Arista" {
            apprefix = "lom"
        }
    }
}

func GetPrefix() string {
    return apprefix
}

/* setAgentName is used to set the agent name for all log messages */
var agentName string

func SetAgentName(a string) {
    agentName = a
    if len(a) == 0 {
        agentName = "lom"
    }
}

func GetAgentName() string {
    return agentName
}

func getPrefix(skip int, severityLevel string) string {
    caller := ""
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
            c -= 1 /* go for 2 if you can. Note: with leading slash first is null */
        }
        /* prefix = caller/t.go, for the example above */
        caller = fmt.Sprintf("%s:%d:", strings.Join(l[c-1:], "/"), ln)
    }

    if vendor == "Arista" {
        // Example message : LOM_PLUGIN_MGR-5-proc_0: pluginmgr_common/pluginmgr_helper.go:955:plugin_mgr: Starting Plugin Manager in PROD mode
        return fmt.Sprintf("%s-%s-%s: %s", agentName, severityLevel, apprefix, caller)
    }
    return apprefix + time.Now().Format("2006-01-02T15:04:05.000") + ": " + caller
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
    m := fmt.Sprintf(getPrefix(skip+2, fmt.Sprintf("%d", lvl))+s, a...)
    if lvl <= ct_lvl {
        if vendor == "Arista" {
            // Example message : %LOM_PLUGIN_MGR-5-proc_0: pluginmgr_common/pluginmgr_helper.go:955:plugin_mgr: Starting Plugin Manager in PROD mode
            FmtFprintf(writers[lvl], "%%"+m+logSuffix)
        } else {
            FmtFprintf(writers[lvl], m+logSuffix)
        }
    }
    return m
}

func LogMessage(lvl syslog.Priority, s string, a ...interface{}) string {
    return LogMessageWithSkip(2, lvl, s, a...)
}

/* Log this message for panic level and exit */
func LogPanic(s string, a ...interface{}) {
    s = LogMessage(syslog.LOG_CRIT, s+"LoM exiting ...", a...)
    DoPanic(s)
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
func LogCritical(s string, a ...interface{}) error {
    lastError = errors.New(LogMessage(syslog.LOG_CRIT, s, a...))
    return lastError
}

/* Log this message at error level */
func LogError(s string, a ...interface{}) error {
    lastError = errors.New(LogMessage(syslog.LOG_ERR, s, a...))
    return lastError
}

/* Log this message at warning level */
func LogWarning(s string, a ...interface{}) {
    LogMessage(syslog.LOG_WARNING, s, a...)
}

/* Log this message at info level */
func LogInfo(s string, a ...interface{}) {
    LogMessage(syslog.LOG_INFO, s, a...)
}

/* Log this message at debug level */
func LogDebug(s string, a ...interface{}) {
    LogMessage(syslog.LOG_DEBUG, s, a...)
}

/*
 * System Shutdown
 */
type sysShutdown_t struct {
    ch       chan int
    wg       *sync.WaitGroup
    shutdown bool
}

/*
 * SysShutDown:
 *
 * Routines that run for the lifetime of LoM process can call
 * register with a caller string indicating the caller.
 * The caller is expected to listen on the returned channel.
 * For any data on the returned channel, it implies system is
 * shutting down. The routine may do any cleanup and exit.
 * Just as a last step before exit, call deregister with the
 * same caller string.
 *
 * Register & deregister calls are logged to enable any debugging.
 */

func (p *sysShutdown_t) register(caller string) <-chan int {
    if !p.shutdown {
        LogMessageWithSkip(2, syslog.LOG_DEBUG, "sysShutdown_t:Register by (%s)", caller)
        p.wg.Add(1)
        return p.ch
    } else {
        LogError("Failed to register (%s) as shutdown in progress", caller)
        return nil
    }
}

func (p *sysShutdown_t) deregister(caller string) {
    /* Log the message with caller info */
    LogMessageWithSkip(2, syslog.LOG_DEBUG, "sysShutdown_t:Deregister by (%s)", caller)
    p.wg.Done()
}

func (p *sysShutdown_t) doShutdown(toutSecs int) {
    if p.shutdown {
        LogError("Shutdown already in progress")
        return
    }
    p.shutdown = true

    /* Close channel - to help all listeners get default data immediately */
    close(p.ch)

    /* Buffer of 1 is useful in case of timeout, as there will not be any reader */
    chEnd := make(chan int, 1)

    go func() {
        /* Wait until all go down & indicate */
        p.wg.Wait()
        chEnd <- 0 /* write will not block */
    }()

    /* Waited forever or given period */
    WaitedSecs := 0
    for {
        select {
        case <-chEnd:
            LogDebug("All routines terminated")
            return

        case <-time.After(time.Second):
            WaitedSecs++
            if (toutSecs > 0) && (WaitedSecs >= toutSecs) {
                LogError("Not all routines terminated. toutSecs(%d)", toutSecs)
                return
            }
            LogDebug("Waiting for go routines termination waited (%d) secs", WaitedSecs)
        }
    }
}

var sysShutdown *sysShutdown_t

func InitSysShutdown() {
    /* 20 - Just some initial capacity. */
    sysShutdown = &sysShutdown_t{make(chan int, 20), new(sync.WaitGroup), false}
}

func init() {
    InitSysShutdown()
}

func RegisterForSysShutdown(caller string) <-chan int {
    return sysShutdown.register(caller)
}

func DeregisterForSysShutdown(caller string) {
    sysShutdown.deregister(caller)
}

func DoSysShutdown(toutSecs int) {
    sysShutdown.doShutdown(toutSecs)
}

func IsSysShuttingDown() bool {
    return sysShutdown.shutdown
}

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

/*
 * Log Periodic module
 */

const A_DAY_IN_SECS = int64(24 * 60 * 60)

/* Info related to logging periodically */
type LogPeriodicEntry_t struct {
    ID      string          /* Identifier provided by caller */
    Message string          /* string to log */
    Lvl     syslog.Priority /* Log Level to use */
    Period  int             /* period in seconds */
    /*
     * TODO: Change period to list of {period, cnt}
     * after finishing cnt writes, move to next entry in list.
     * Caller may send [ {5, 100}, {3600, 0} ], implying
     * Write first 100 logs for every 5 seconds. After that
     * write logs for every hour forever (cnt = 0)
     */
}

type logPeriodicEntryInt_t struct {
    LogPeriodicEntry_t
    Due   int64  /* Next due epoch time point */
    index uint64 /* Add a sequential index to the message */
    /*
     * This can help identify repeated logs with index
     * indicating set to count of logs written so far
     */
}

/* Log Periodic module */
type logPeriodic_t struct {
    /* Channel to communicate to logging routine */
    logCh chan *LogPeriodicEntry_t

    logPeriodicList   map[string]*logPeriodicEntryInt_t
    logPeriodicSorted []*logPeriodicEntryInt_t

    /*
     * TODO: Any entry after logging repeatedly at set period
     * for a day or two, reduce the period to every hour
     * No point in polluting logs, as we have screamed enough
     */
}

var logPeriodic *logPeriodic_t

/* Get Log Periodic instance */
func GetlogPeriodic() *logPeriodic_t {
    if logPeriodic != nil {
        return logPeriodic
    }
    logPeriodicInit()
    return logPeriodic
}

/* Initialize the singleton instance for log periodic */
func logPeriodicInit() {
    logPeriodic = &logPeriodic_t{
        logCh:             make(chan *LogPeriodicEntry_t),
        logPeriodicList:   make(map[string]*logPeriodicEntryInt_t),
        logPeriodicSorted: nil,
    }

    go logPeriodic.run()
}

/* Helper to add a log periodic entry */
func (p *logPeriodic_t) AddLogPeriodic(l *LogPeriodicEntry_t) error {
    if (len(l.ID) == 0) || (len(l.Message) == 0) {
        return LogError("LogPeriodicEntry ID or message is empty")
    }
    min := GetConfigMgr().GetGlobalCfgInt("MIN_PERIODIC_LOG_PERIOD_SECS")
    if l.Period < min {
        return LogError("LogPeriodicEntry Period(%v) < min(%v)", l.Period, min)
    }
    p.logCh <- l
    return nil
}

/* Helper to remove a previouslu added log periodic entry */
func (p *logPeriodic_t) DropLogPeriodic(ID string) {
    if len(ID) > 0 {
        /* Emtpy Message implies drop */
        p.logCh <- &LogPeriodicEntry_t{ID: ID}
    }
}

func (p *logPeriodic_t) run() {
    tout := A_DAY_IN_SECS /* Just a init value; Once per day */
    shutId := "logPeriodic"
    chAbort := RegisterForSysShutdown(shutId)

    defer func() {
        DeregisterForSysShutdown(shutId)
    }()

    for {
        upd := false
        select {
        case l := <-p.logCh:
            upd = p.update(l)

        case <-time.After(time.Duration(tout) * time.Second):
            upd = p.writeLogs()

        case <-chAbort:
            LogDebug("Terminating LogPeriodic upon explicit abort")
            logPeriodic = nil
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
            p.logPeriodicList[l.ID] = &logPeriodicEntryInt_t{*l, 0, 0} /* Set Due immediate */
            upd = true
        }
    } else if ok {
        delete(p.logPeriodicList, l.ID)
        upd = true
    }
    if upd {
        p.logPeriodicSorted = make([]*logPeriodicEntryInt_t, len(p.logPeriodicList))

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

/*
 * Log Periodic Helpers  -----------------------------------------------------------------
 */

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

/* Helper to add a periodic log entry with short timeout and long timeout
* This function will add periodic log entry with short timeout and then update the timeout to long timeout
* after short timeout expiry. This function will also listen for stop signal to remove the periodic log entry
* before long timeout expiry.
* Note : This is one time call API. Use channel to stop the logperiodic. Do not remove periodic entry or update timeout
* Min time >= MIN_PERIODIC_LOG_PERIOD_SECS
 */
func AddPeriodicLogWithTimeouts(ID string, message string, shortTimeout time.Duration,
    longTimeout time.Duration) chan bool {
    // Create a channel to listen for stop signals to kill timer
    stopchannel := make(chan bool)

    GetGoroutineTracker().Start("AddPeriodicLogWithTimeouts_"+ID, func() {
        // First add periodic log with short timeout
        AddPeriodicLogInfo(ID, message, int(math.Round(shortTimeout.Seconds()))) // call lomcommon framework

        // Wait for the short timeout to expire or for stop signal
        select {
        case <-time.After(shortTimeout):
            // after short timeout expiry, update timer to longtimeout
            UpdatePeriodicLogTime(ID, int(longTimeout.Seconds()))
            break
        case <-stopchannel:
            RemovePeriodicLogEntry(ID)
            return
        }

        // Wait for the stop signal
        <-stopchannel

        // Stop signal received, remove the periodic log entry
        RemovePeriodicLogEntry(ID)
    })

    return stopchannel
}

/*
 * Oneshot Timer  -----------------------------------------------------------------
 */

type OneShotEntry_t struct {
    due     int64  /* Time point of firing as epoch secconds */
    msg     string /* Just info only; Used for logging */
    f       func() /* Function to call upon due */
    disable bool   /* == true, f will not be called, if set before due */
    done    bool   /* Set to true, upon firing / calling f */
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
    ch               chan *OneShotEntry_t /* Caller reqs are sent to handler via this chan */
    initOneShotTimer bool                 /* True - Upon first request, initialized */
}

var oneShotTimer = oneShotTimer_t{make(chan *OneShotEntry_t, 1), false}

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
    tmr := &OneShotEntry_t{due: time.Now().Unix() + tout, msg: msg, f: f}
    oneShotTimer.ch <- tmr
    if !oneShotTimer.initOneShotTimer {
        oneShotTimer.initOneShotTimer = true
        go oneShotTimer.runOneShotTimer()
        LogDebug("Started oneShotTimer.runOneShotTimer")
    }
    LogMessageWithSkip(1, syslog.LOG_DEBUG, "oneShotTimer: (%v) (%s)", tout, msg)
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
        for k, l := range all {
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
        for i := 0; i < cnt; i++ {
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
/* TODO: Replace with global abort channel later */
func (p *oneShotTimer_t) runOneShotTimer() {
    all := make(map[int64][]*OneShotEntry_t)
    shutId := "runOneShotTimer"
    chAbort := RegisterForSysShutdown(shutId)

    defer func() {
        DeregisterForSysShutdown(shutId)
    }()

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
        case tmr := <-p.ch:
            all[tmr.due] = append(all[tmr.due], tmr)

        case <-time.After(time.Duration(tout) * time.Second):

        case <-chAbort:
            LogInfo("runOneShotTimer: System abort called. terminating...")
            return
        }
    }
}

/*
 * Go Routine Tracker  -----------------------------------------------------------------
 */

/*
 * TODO: Goutham : Add a run method which will carry a non-zero timeout.
 * This method will block until either the called routine returns or timeout fires.,
 * whichever occurs earlier. If timeout fires, it kick off periodic log message
 * and stop the message upon the routine returns.
 */

/* TODO: Goutham : For WaitAll, accept a systemwide channel which will timeout the function */

/*
 * GoroutineTracker is a helper for tracking goroutines. It can be used to
 * (a) Track all goroutines
 * (b) wait on specific goroutine to finish
 * (c) Get status of all goroutines
 * (d) Get status of specific goroutine
 */

var goroutineTracker *GoroutineTracker = nil

type Goroutine struct {
    done      chan struct{}
    StartTime time.Time
}

type GoroutineInfo struct {
    Goroutine
    Name     string
    Duration time.Duration
}

type GoroutineTracker struct {
    mlock      sync.Mutex
    goroutines map[string]*Goroutine
    waitGroup  sync.WaitGroup
}

/*
 * Create a new GoroutineTracker and return GoroutineTracker instance
 *
 * Parameters:
 * - None:
 *
 * Returns:
 * - pointer to a new GoroutineTracker instance:
 */
func GetGoroutineTracker() *GoroutineTracker {
    if goroutineTracker != nil {
        return goroutineTracker
    }
    goroutineTracker = &GoroutineTracker{
        mlock:      sync.Mutex{},
        goroutines: make(map[string]*Goroutine),
        waitGroup:  sync.WaitGroup{},
    }
    return goroutineTracker
}

/*
 * Start a goroutine with given name. If a goroutine with same name already exists, then it panics
 * Returns true if the goroutine is runing, false otherwise.
 *
 * Parameters:
 * - name: the name of the goroutine
 * - fn  : Function to be called
 * - args - Arguments to be passed to the function
 *
 * Returns:
 * - None:
 */
func (grt *GoroutineTracker) Start(name string, fn interface{}, args ...interface{}) {
    grt.mlock.Lock()
    defer grt.mlock.Unlock()

    if _, ok := grt.goroutines[name]; ok {
        /* Goroutine with same name already exists & active */
        panic(fmt.Sprintf("Cannot start goroutine, %q as its active", name))
    }

    g := &Goroutine{done: make(chan struct{}), StartTime: time.Now()}
    grt.goroutines[name] = g
    grt.waitGroup.Add(1)

    /* Start the goroutine */
    go func() {
        defer func() {
            grt.mlock.Lock()
            defer grt.mlock.Unlock()

            grt.waitGroup.Done()

            /* Delete the goroutine from the map if it is finished */
            LogDebug("Goroutine %s is finished at %q. Deleting it from goroutine tracker", name, time.Now().Format("January 02, 2006 15:04:05.000000"))
            delete(grt.goroutines, name)

            close(g.done)
        }()

        /* Get the reflect.Value of the function */
        f := reflect.ValueOf(fn)

        /* If the function is not a valid type, panic with an error message */
        if f.Kind() != reflect.Func {
            panic("Invalid function type provided to Start method of GoroutineTracker instance with name " + name + "")
        }

        /* If arguments are provided, call the function with the arguments */
        LogDebug("Goroutine %s started at %q", name, time.Now().Format("January 02, 2006 15:04:05.000000"))
        if len(args) > 0 {
            /* Convert the arguments to a slice of reflect.Value */
            argVals := make([]reflect.Value, len(args))
            for i, arg := range args {
                argVals[i] = reflect.ValueOf(arg)
            }

            /* Call the function with the arguments */
            f.Call(argVals)
        } else {
            /* Call the function without arguments */
            f.Call(nil)
        }
    }()
}

/*
 * Wait for a goroutine with given name to finish.
 * CAUTION : This may bocks on channel. So, it should be called in a separate goroutine
 * Parameters:
 * - name: the name of the goroutine to check
 *
 * Returns:
 * - bool:
 */
func (grt *GoroutineTracker) Wait(name string) {

    grt.mlock.Lock()
    g, ok := grt.goroutines[name]
    grt.mlock.Unlock()

    if ok {
        <-g.done
    }
}

/*
 * Wait for a all the goroutine to finish.
 * CAUTION : This blocks as intended. Do only one call per process.
 * Do not create any goroutines after this call
 * Parameters:
 * - timeout: timeout in seconds. If timeout is 0, then it waits forever
 *
 * Returns:
 * - bool: true if all goroutines finished within timeout, false otherwise
 */
func (grt *GoroutineTracker) WaitAll(timeout time.Duration) bool {
    finishchan := make(chan struct{})
    go func() {
        grt.waitGroup.Wait()
        close(finishchan)
    }()

    if timeout == 0 {
        <-finishchan
        return true
    }

    select {
    case <-finishchan:
        return true
    case <-time.After(timeout):
        LogInfo("WaitAll timed out after %v", timeout)
        return false
    }
}

/*
 * Checks if a goroutine with the given name is currently running or not.
 * Returns true if the goroutine is running, false otherwise.
 *
 * Parameters:
 * - name: the name of the goroutine to check
 *
 * Returns:
 * - bool: status of goroutine
 * - error: error if goroutine with given name doesn't exist
 */
func (grt *GoroutineTracker) IsRunning(name string) (bool, error) {
    grt.mlock.Lock()
    defer grt.mlock.Unlock()

    if _, ok := grt.goroutines[name]; ok {
        return true, nil
    }

    /* Goroutine with given name doesn't exist */
    return false, fmt.Errorf("Goroutine with name %q doesn't exist", name)
}

/*
 * Gets the start time of a goroutine with the given name. It must be running
 * Parameters:
 * - name: the name of the goroutine
 *
 * Returns:
 * - string: start time of the goroutine
 * - error: error if goroutine with given name doesn't exist
 */
func (grt *GoroutineTracker) GetTimeStarted(name string) (string, error) {
    grt.mlock.Lock()
    defer grt.mlock.Unlock()

    if g, ok := grt.goroutines[name]; ok { /* if goroutine exists */
        return g.StartTime.String(), nil
    }

    /* Goroutine with given name doesn't exist */
    return "", fmt.Errorf("Goroutine with name %q doesn't exist", name)
}

/*
 * Returns a list of GoroutineInfo. If name is nil then return info for all the goroutines being tracked
 * If name is given, then return info for that goroutine
 * Parameters:
 * - name: the name of the goroutine
 *
 * Returns:
 * - []interface{}: list of GoroutineInfo
 */
func (grt *GoroutineTracker) InfoList(name *string) []interface{} {
    grt.mlock.Lock()
    defer grt.mlock.Unlock()

    /* Create a function to extract info for a given goroutine */
    extractInfo := func(name string, g *Goroutine) GoroutineInfo {
        duration := time.Since(g.StartTime)
        return GoroutineInfo{
            Goroutine: *g,
            Name:      name,
            Duration:  duration,
        }
    }

    /* If name is given, return info for that goroutine */
    if name != nil && *name != "" {
        if g, ok := grt.goroutines[*name]; ok {
            return []interface{}{extractInfo(*name, g)}
        }
        return []interface{}{}
    }

    /* Return info for all goroutines */
    var list []interface{}
    for name, g := range grt.goroutines {
        if g != nil {
            list = append(list, extractInfo(name, g))
        }
    }

    return list
}

/*
 * PrintGoroutineInfo prints the information of all goroutines to syslog
 * Parameters:
 * - name: the name of the goroutine. If name is empty, then info for all goroutines is printed
 * Returns:
 * - None
 */
func PrintGoroutineInfo(name string) {
    if goroutineTracker == nil {
        LogInfo("GoroutineTracker is not initialized.")
        return
    }

    infoList := goroutineTracker.InfoList(&name)

    if len(infoList) == 0 {
        LogInfo("No goroutine information available.")
        return
    }

    for _, info := range infoList {
        goroutineInfo, ok := info.(GoroutineInfo)
        if ok {
            if name == "" || goroutineInfo.Name == name {
                LogInfo("------------------------------")
                LogInfo("Goroutine:")
                LogInfo("  Name:%q", goroutineInfo.Name)
                LogInfo("  Status: Running")
                LogInfo("  StartTime:%q:", goroutineInfo.Goroutine.StartTime.Format("January 02, 2006 15:04:05.000000"))
                LogInfo("  Duration:%q", goroutineInfo.Duration)
                LogInfo("------------------------------")
            }
        }
    }
}

/*
 * Read environment variables
 */

func xyz() {
}

var envMap = map[string]string{}

/* variable name , system env variable name, default value*/
const EnvMapDefinitionsStr = `{
    "ENV_lom_conf_location": {
        "env": "LOM_CONF_LOCATION",
        "default": "" 
    }
}`

/*
 * key is EnvMapDefinitionsStr keys. Value is string. If its "", then no value exists.
 * Convert them to appropriate before usage.
 * e.g. ENV_lom_conf_location -> "path/to/conf"
 */

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
    if len(envMap) == 0 {
        LoadEnvironmentVariables()
    }
    value, exists := envMap[envname]
    return value, exists
}

func ValidatedVal(sval string, max, min, def int, name string) int {
    val, err := strconv.Atoi(sval)

    if (err != nil) || (val > max) || (val < min) {
        LogWarning("%s failed validation. err(%v) sval(%s) ret(%d) min(%d) max(%d)",
            name, err, sval, def, min, max)
        return def
    }
    return val
}

/* Good helper
 *
 *func JsonEqual(a, b []byte) (bool, error) {
 *    var j1, j2 interface{}
 *    var err error
 *    if err = json.Unmarshal(a, &j1); err != nil {
 *        return false, err
 *    }
 *    if err = json.Unmarshal(b, &j2); err != nil {
 *        return false, err
 *    }
 *    return reflect.DeepEqual(j1, j2), nil
 *}
 *
 */
