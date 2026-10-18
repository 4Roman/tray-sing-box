package domain

import (
	"strings"
	"testing"
)

func okResult(tag string, ms int) LatencyResult {
	return LatencyResult{Tag: tag, Type: "vless", Status: LatencyOK, DelayMs: ms, Eligible: true}
}

func latencyReport(results ...LatencyResult) *LatencyReport {
	return &LatencyReport{Results: results}
}

func nodeRouting(tag string) RoutingTarget {
	return RoutingTarget{Kind: RoutingNode, Tag: tag, ProxyRefs: []string{tag}, Final: tag}
}

func selectorRouting(tag string) RoutingTarget {
	return RoutingTarget{Kind: RoutingSelector, Tag: tag, Groups: []string{tag}, Final: tag}
}

// The order of ChooseFastest's checks and what each case says
func TestChooseFastest(t *testing.T) {
	timeout := LatencyResult{Tag: "a", Type: "vless", Status: LatencyTimeout, Eligible: true}
	relay := okResult("a", 50)
	relay.Eligible = false
	dpi := LatencyResult{Tag: "dpi-bypass", Type: "http", Status: LatencyOK, DelayMs: 10}
	group := LatencyResult{Tag: "proxy", Type: "selector", Status: LatencySkipped, Note: "группа — проверяются её серверы"}
	splitSeven := RoutingTarget{Kind: RoutingNode, Tag: "a", ProxyRefs: []string{"a", "b", "c", "d", "e", "f", "g"}, Final: "g"}
	withRules := selectorRouting("proxy")
	withRules.InRules = true
	partial := RoutingTarget{Kind: RoutingSelector, Tag: "proxy", Groups: []string{"proxy"}, Final: "direct", InRules: true}

	cases := []struct {
		name    string
		report  *LatencyReport
		rt      RoutingTarget
		confirm bool
		want    FastestOutcome
	}{
		{"switch to the fastest", latencyReport(okResult("a", 200), okResult("b", 100)), nodeRouting("a"), false,
			FastestOutcome{Tag: "b", Previous: "a", DelayMs: 100, PrevMs: 200, Switched: true,
				Message: "Выбран самый быстрый — «b» (100 мс; был «a» — 200 мс)."}},
		// max(30 ms, 15 %): for 100 ms the 30 ms count
		{"kept within 30 ms", latencyReport(okResult("a", 130), okResult("b", 100)), nodeRouting("a"), false,
			FastestOutcome{Tag: "b", Previous: "a", DelayMs: 100, PrevMs: 130,
				Message: "Текущий сервер «a» и так среди самых быстрых (130 мс; лучший — «b», 100 мс). Ничего не изменено."}},
		{"switched beyond 30 ms", latencyReport(okResult("a", 131), okResult("b", 100)), nodeRouting("a"), false,
			FastestOutcome{Tag: "b", Previous: "a", DelayMs: 100, PrevMs: 131, Switched: true,
				Message: "Выбран самый быстрый — «b» (100 мс; был «a» — 131 мс)."}},
		// ... for 400 ms the 15 % (60 ms)
		{"kept within 15 %", latencyReport(okResult("a", 460), okResult("b", 400)), nodeRouting("a"), false,
			FastestOutcome{Tag: "b", Previous: "a", DelayMs: 400, PrevMs: 460,
				Message: "Текущий сервер «a» и так среди самых быстрых (460 мс; лучший — «b», 400 мс). Ничего не изменено."}},
		{"switched beyond 15 %", latencyReport(okResult("a", 461), okResult("b", 400)), nodeRouting("a"), false,
			FastestOutcome{Tag: "b", Previous: "a", DelayMs: 400, PrevMs: 461, Switched: true,
				Message: "Выбран самый быстрый — «b» (400 мс; был «a» — 461 мс)."}},
		{"the current server is the fastest", latencyReport(okResult("a", 80), okResult("b", 100)), nodeRouting("a"), false,
			FastestOutcome{Tag: "a", Previous: "a", DelayMs: 80, PrevMs: 80,
				Message: "Текущий сервер «a» и так самый быстрый (80 мс). Ничего не изменено."}},
		{"the current server did not answer", latencyReport(timeout, okResult("b", 100)), nodeRouting("a"), false,
			FastestOutcome{Tag: "b", Previous: "a", DelayMs: 100, Switched: true,
				Message: "Выбран самый быстрый — «b» (100 мс; был «a» — нет ответа)."}},
		// A relay or the DPI bypass carrying the traffic is no server to keep
		{"the current server is not eligible", latencyReport(relay, okResult("b", 100)), nodeRouting("a"), false,
			FastestOutcome{Tag: "b", Previous: "a", DelayMs: 100, PrevMs: 50, Switched: true,
				Message: "Выбран самый быстрый — «b» (100 мс; был «a» — 50 мс)."}},
		{"the current server is gone from the report", latencyReport(okResult("b", 100)), nodeRouting("a"), false,
			FastestOutcome{Tag: "b", Previous: "a", DelayMs: 100, Switched: true,
				Message: "Выбран самый быстрый — «b» (100 мс; был «a» — не проверялся)."}},
		{"urltest picks the fastest itself", latencyReport(okResult("b", 100)), RoutingTarget{Kind: RoutingURLTest, Tag: "auto", Groups: []string{"auto"}, Final: "auto"}, true,
			FastestOutcome{Previous: "auto", Message: "Трафик идёт через группу urltest «auto» — она сама выбирает самый быстрый сервер. Ничего не изменено."}},
		{"split between two servers", latencyReport(okResult("b", 100)), RoutingTarget{Kind: RoutingNode, Tag: "a", ProxyRefs: []string{"a", "b"}, Final: "b", InRules: true}, true,
			FastestOutcome{Message: "Правила маршрутизации ведут трафик на разные серверы («a», «b») — «самый быстрый» направил бы всё на один. Выберите сервер вручную."}},
		// SwitchOutbound would repoint the server and leave the group
		{"split between a server and a group", latencyReport(okResult("b", 100)), RoutingTarget{Kind: RoutingNode, Tag: "a", ProxyRefs: []string{"a"}, Groups: []string{"auto"}, Final: "auto", InRules: true}, false,
			FastestOutcome{Message: "Правила маршрутизации ведут трафик на разные серверы («a», «auto») — «самый быстрый» направил бы всё на один. Выберите сервер вручную."}},
		{"a long split is named in part", latencyReport(okResult("b", 100)), splitSeven, false,
			FastestOutcome{Message: "Правила маршрутизации ведут трафик на разные серверы («a», «b», «c», «d», «e», …и ещё 2) — «самый быстрый» направил бы всё на один. Выберите сервер вручную."}},
		{"a selector needs a confirmation", latencyReport(group, okResult("b", 100)), selectorRouting("proxy"), false,
			FastestOutcome{Tag: "b", Previous: "proxy", DelayMs: 100, NeedsConfirm: true,
				Message: "Сейчас трафик идёт через группу «proxy». «Выбрать самый быстрый», как и выбор вручную, направит его прямо на «b» (группа останется в конфиге). Продолжить?"}},
		// Rules naming the group stay on it: the question says so
		{"a selector named by rules too", latencyReport(group, okResult("b", 100)), withRules, false,
			FastestOutcome{Tag: "b", Previous: "proxy", DelayMs: 100, NeedsConfirm: true,
				Message: "Сейчас трафик идёт через группу «proxy». «Выбрать самый быстрый», как и выбор вручную, направит прямо на «b» трафик route.final; правила маршрутизации, которые ведут на группу, останутся на ней (группа останется в конфиге). Продолжить?"}},
		{"a selector confirmed", latencyReport(group, okResult("b", 100)), selectorRouting("proxy"), true,
			FastestOutcome{Tag: "b", Previous: "proxy", DelayMs: 100, Switched: true,
				Message: "Выбран самый быстрый — «b» (100 мс; был «proxy» — группа)."}},
		// The switch would route what goes direct now through the server
		{"a selector for a part of the traffic", latencyReport(group, okResult("b", 100)), partial, true,
			FastestOutcome{Previous: "proxy", Message: "Через группу «proxy» идёт только трафик по правилам маршрутизации, остальной идёт мимо неё (route.final — «direct») — «самый быстрый» направил бы через сервер и его. Ничего не изменено."}},
		{"none answered", latencyReport(timeout, LatencyResult{Tag: "b", Status: LatencyError, Eligible: true}), nodeRouting("a"), false,
			FastestOutcome{Message: "Ни один сервер не ответил — активный сервер не изменён."}},
		{"only servers that are never chosen answered", latencyReport(dpi, timeout), nodeRouting("a"), false,
			FastestOutcome{Message: "Ответили только серверы, которые не выбираются самыми быстрыми (обход DPI, промежуточные узлы цепочек) — активный сервер не изменён."}},
		{"the DPI bypass is never the fastest", latencyReport(dpi, okResult("a", 300), okResult("b", 100)), nodeRouting("a"), false,
			FastestOutcome{Tag: "b", Previous: "a", DelayMs: 100, PrevMs: 300, Switched: true,
				Message: "Выбран самый быстрый — «b» (100 мс; был «a» — 300 мс)."}},
		{"a tie goes to the order of the config", latencyReport(okResult("a", 300), okResult("c", 100), okResult("b", 100)), nodeRouting("a"), false,
			FastestOutcome{Tag: "c", Previous: "a", DelayMs: 100, PrevMs: 300, Switched: true,
				Message: "Выбран самый быстрый — «c» (100 мс; был «a» — 300 мс)."}},
		{"nothing went through a server", latencyReport(okResult("b", 100)), RoutingTarget{Final: "direct"}, false,
			FastestOutcome{Tag: "b", DelayMs: 100, Switched: true, Message: "Выбран самый быстрый — «b» (100 мс)."}},
		// A WireGuard endpoint takes the traffic: the switch would move all of
		// it off a tunnel the check never measured
		{"an endpoint carries the traffic", latencyReport(okResult("b", 100)), RoutingTarget{Kind: RoutingEndpoint, Tag: "wg", Final: "wg"}, true,
			FastestOutcome{Previous: "wg", Message: "Трафик идёт через endpoint «wg» — проверка его не измеряет; выберите сервер вручную."}},
		{"an endpoint by a rule", latencyReport(okResult("b", 100)), RoutingTarget{Kind: RoutingEndpoint, Tag: "warp\nWARP", Final: "direct", InRules: true}, false,
			FastestOutcome{Previous: "warp\nWARP", Message: "Трафик идёт через endpoint «warp WARP» — проверка его не измеряет; выберите сервер вручную."}},
		{"nobody answered, an endpoint carries the traffic", latencyReport(timeout), RoutingTarget{Kind: RoutingEndpoint, Tag: "wg", Final: "wg"}, false,
			FastestOutcome{Previous: "wg", Message: "Трафик идёт через endpoint «wg» — проверка его не измеряет; выберите сервер вручную."}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ChooseFastest(tc.report, tc.rt, tc.confirm); got != tc.want {
				t.Errorf("ChooseFastest =\n %+v\nwant\n %+v", got, tc.want)
			}
		})
	}
}

// A provider's name in a message stays on one line
func TestChooseFastestNamesOnOneLine(t *testing.T) {
	got := ChooseFastest(latencyReport(okResult("de\n\nПодписка истекла", 100)), RoutingTarget{Final: "direct"}, false)
	if strings.Contains(got.Message, "\n") || !strings.Contains(got.Message, "«de  Подписка истекла»") {
		t.Fatalf("message = %q", got.Message)
	}
}

// The text of a switch made: the restart and the DPI chain left behind
func TestSwitchMessage(t *testing.T) {
	r := latencyReport(okResult("a", 200), okResult("b", 100))
	o := FastestOutcome{Tag: "b", Previous: "a", DelayMs: 100, Switched: true, Restarted: true, DPIWas: "a"}
	want := "Выбран самый быстрый — «b» (100 мс; был «a» — 200 мс), VPN перезапущен.\n" +
		"Обход DPI был включён для «a». Для нового сервера включите его заново (раздел «Обход DPI»)."
	if got := switchMessage(o, r); got != want {
		t.Fatalf("switchMessage =\n%s\nwant\n%s", got, want)
	}
}
