package domain

import (
	"fmt"
	"slices"
	"strings"

	"tray-sing-box/internal/config"
)

// The texts of "select the fastest", as the page and the tray show them
const (
	msgFastestSwitched     = "Выбран самый быстрый — «%s» (%d мс; был «%s» — %s)"
	msgFastestSwitchedNew  = "Выбран самый быстрый — «%s» (%d мс)" // nothing went through a server before
	msgFastestRestarted    = ", VPN перезапущен"
	msgFastestKeep         = "Текущий сервер «%s» и так среди самых быстрых (%d мс; лучший — «%s», %d мс). Ничего не изменено."
	msgFastestKeepBest     = "Текущий сервер «%s» и так самый быстрый (%d мс). Ничего не изменено."
	msgFastestNone         = "Ни один сервер не ответил — активный сервер не изменён."
	msgFastestNoneEligible = "Ответили только серверы, которые не выбираются самыми быстрыми (обход DPI, промежуточные узлы цепочек) — активный сервер не изменён."
	msgFastestURLTest      = "Трафик идёт через группу urltest «%s» — она сама выбирает самый быстрый сервер. Ничего не изменено."
	msgFastestSplit        = "Правила маршрутизации ведут трафик на разные серверы (%s) — «самый быстрый» направил бы всё на один. Выберите сервер вручную."
	msgFastestPartial      = "Через группу «%s» идёт только трафик по правилам маршрутизации, остальной идёт мимо неё (route.final — «%s») — «самый быстрый» направил бы через сервер и его. Ничего не изменено."
	msgFastestConfirm      = "Сейчас трафик идёт через группу «%s». «Выбрать самый быстрый», как и выбор вручную, направит его прямо на «%s» (группа останется в конфиге). Продолжить?"
	msgFastestConfirmRules = "Сейчас трафик идёт через группу «%s». «Выбрать самый быстрый», как и выбор вручную, направит прямо на «%s» трафик route.final; правила маршрутизации, которые ведут на группу, останутся на ней (группа останется в конфиге). Продолжить?"
	msgFastestDPI          = "Обход DPI был включён для «%s». Для нового сервера включите его заново (раздел «Обход DPI»)."
	msgFastestGone         = "Сервер «%s» пропал из конфига во время проверки (обновилась подписка?) — повторите."
)

// splitNamesLimit bounds the servers a split-routing refusal names
const splitNamesLimit = 5

// ChooseFastest decides what "select the fastest" does with a report, for
// the routing as it is (rt). In this order:
//
//  1. the traffic goes through a urltest group: it picks the fastest itself
//     — refused;
//  2. the routing sends traffic to two or more servers or groups: switching
//     would send all of it to one (SwitchOutbound repoints every proxy and
//     leaves the groups) — refused;
//  3. the fastest server is the eligible one with the lowest delay (the
//     first in the config on a tie); none answered — refused;
//  4. the current server answered and is slower than the fastest by at most
//     max(FastestKeepMarginMs, FastestKeepMarginPct %) — kept, nothing is
//     saved (a few milliseconds are no reason for a restart);
//  5. the traffic goes through a selector group: the switch replaces the
//     group with the server — only when route.final is the group (otherwise
//     the traffic that does not go through it would be routed through the
//     server too: refused), and only once the user confirmed
//     (NeedsConfirm, Message is the question);
//  6. otherwise the switch: Switched says the routing is to be moved to Tag
//     (SelectFastest makes it and completes the outcome).
//
// Tag is the fastest server (empty when refused), Previous what the traffic
// goes through now.
func ChooseFastest(r *LatencyReport, rt RoutingTarget, confirm bool) FastestOutcome {
	if rt.Kind == RoutingURLTest {
		return FastestOutcome{Previous: rt.Tag, Message: fmt.Sprintf(msgFastestURLTest, DisplayName(rt.Tag))}
	}
	if dest := destinations(rt); len(dest) >= 2 {
		return FastestOutcome{Message: fmt.Sprintf(msgFastestSplit, nameList(dest))}
	}
	best := r.fastest()
	if best == nil {
		if r.answered() {
			return FastestOutcome{Message: msgFastestNoneEligible}
		}
		return FastestOutcome{Message: msgFastestNone}
	}

	o := FastestOutcome{Tag: best.Tag, DelayMs: best.DelayMs}
	switch rt.Kind {
	case RoutingNode:
		o.Previous = rt.Tag
		if cur := r.result(rt.Tag); cur != nil && cur.Status == LatencyOK {
			o.PrevMs = cur.DelayMs
			if cur.Eligible && cur.DelayMs <= best.DelayMs+keepMargin(best.DelayMs) {
				if cur.Tag == best.Tag {
					o.Message = fmt.Sprintf(msgFastestKeepBest, DisplayName(cur.Tag), cur.DelayMs)
				} else {
					o.Message = fmt.Sprintf(msgFastestKeep, DisplayName(cur.Tag), cur.DelayMs, DisplayName(best.Tag), best.DelayMs)
				}
				return o
			}
		}
	case RoutingSelector:
		o.Previous = rt.Tag
		if rt.Final != rt.Tag {
			return FastestOutcome{Previous: rt.Tag, Message: fmt.Sprintf(msgFastestPartial, DisplayName(rt.Tag), DisplayName(rt.Final))}
		}
		if !confirm {
			o.NeedsConfirm = true
			question := msgFastestConfirm
			if rt.InRules {
				question = msgFastestConfirmRules
			}
			o.Message = fmt.Sprintf(question, DisplayName(rt.Tag), DisplayName(best.Tag))
			return o
		}
	}
	o.Switched = true
	o.Message = switchMessage(o, r)
	return o
}

// keepMargin is how much slower than the fastest the current server may be
// and stay
func keepMargin(bestMs int) int {
	return max(config.FastestKeepMarginMs, bestMs*config.FastestKeepMarginPct/100)
}

// destinations are the servers and groups the routing sends traffic to
func destinations(rt RoutingTarget) []string {
	var dest []string
	for _, tag := range append(append([]string{}, rt.ProxyRefs...), rt.Groups...) {
		if !slices.Contains(dest, tag) {
			dest = append(dest, tag)
		}
	}
	return dest
}

// nameList names servers in a message: each on one line and capped, at most
// splitNamesLimit of them
func nameList(tags []string) string {
	names := make([]string, 0, min(len(tags), splitNamesLimit)+1)
	for i, tag := range tags {
		if i == splitNamesLimit {
			names = append(names, fmt.Sprintf("…и ещё %d", len(tags)-i))
			break
		}
		names = append(names, "«"+DisplayName(tag)+"»")
	}
	return strings.Join(names, ", ")
}

// switchMessage is the text of a switch made (or to be made): the fastest
// server, what the traffic went through before, whether the VPN was
// restarted, and the DPI chain left on the previous server
func switchMessage(o FastestOutcome, r *LatencyReport) string {
	var b strings.Builder
	if o.Previous == "" {
		fmt.Fprintf(&b, msgFastestSwitchedNew, DisplayName(o.Tag), o.DelayMs)
	} else {
		fmt.Fprintf(&b, msgFastestSwitched, DisplayName(o.Tag), o.DelayMs, DisplayName(o.Previous), previousText(r.result(o.Previous)))
	}
	if o.Restarted {
		b.WriteString(msgFastestRestarted)
	}
	b.WriteString(".")
	if o.DPIWas != "" {
		b.WriteString("\n")
		fmt.Fprintf(&b, msgFastestDPI, DisplayName(o.DPIWas))
	}
	return b.String()
}

// previousText is what the server the traffic went through before showed
// in the check, as the page marks it
func previousText(r *LatencyResult) string {
	switch {
	case r == nil:
		return "не проверялся"
	case r.Type == "selector" || r.Type == "urltest":
		return "группа"
	case r.Status == LatencyOK:
		return fmt.Sprintf("%d мс", r.DelayMs)
	case r.Status == LatencyTimeout:
		return "нет ответа"
	case r.Status == LatencyError:
		return "ошибка"
	case r.Status == LatencyUnfinished:
		return "не успели"
	}
	return "не проверялся"
}

// fastest is the eligible server with the lowest delay, the first in the
// order of the config on a tie; nil when none of them answered
func (r *LatencyReport) fastest() *LatencyResult {
	var best *LatencyResult
	for i := range r.Results {
		res := &r.Results[i]
		if res.Eligible && res.Status == LatencyOK && (best == nil || res.DelayMs < best.DelayMs) {
			best = res
		}
	}
	return best
}

// answered: some server answered, eligible or not
func (r *LatencyReport) answered() bool {
	for _, res := range r.Results {
		if res.Status == LatencyOK {
			return true
		}
	}
	return false
}

// result is the result of tag, nil when the check did not see it
func (r *LatencyReport) result(tag string) *LatencyResult {
	for i := range r.Results {
		if r.Results[i].Tag == tag {
			return &r.Results[i]
		}
	}
	return nil
}
