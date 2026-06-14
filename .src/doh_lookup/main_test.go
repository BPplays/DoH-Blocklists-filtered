package main

import (
	// "log"
	"fmt"
	"net/netip"
	"reflect"
	"testing"
)


func TestSprintTime(t *testing.T) {

	// ll := netip.MustParseAddr("fe80::53eb:d72c:9d70:5b33")
	// ula := netip.MustParseAddr("fd0e::cafe:babe:beef")
	// gua := netip.MustParseAddr("3fff::cafe:babe:beef")
	//
	// rfc1918 := netip.MustParseAddr("10.0.52.10")

	t.Run("line dedupe test", func(t *testing.T) {
		t.Parallel()

		ips := []Line{
			{
				Host: "first.example.com",
				Addr: netip.MustParseAddr("2001:db8::1"),
			},

			{
				Host: "second.example.com",
				Addr: netip.MustParseAddr("2001:db8::1"),
			},


			{
				Host: "2.example.com",
				Addr: netip.MustParseAddr("2001:db8::2"),
			},

			{
				Host: "second.2.example.com",
				Addr: netip.MustParseAddr("2001:db8::2"),
				ExtraHosts: []string{},
			},
		}

		ips_check := []Line{
			{
				Host: "first.example.com",
				Addr: netip.MustParseAddr("2001:db8::1"),
				ExtraHosts: []string{"second.example.com"},
			},

			{
				Host: "2.example.com",
				Addr: netip.MustParseAddr("2001:db8::2"),
				ExtraHosts: []string{"second.2.example.com"},
			},
		}

		depips := lineDedupeIps(ips)

		if !reflect.DeepEqual(depips, ips_check) {
			fmt.Println(depips)
			fmt.Println(ips_check)
			fmt.Println()
			fmt.Printf("%#v\n", depips)
			fmt.Printf("%#v\n", ips_check)
			t.Fail()
		}
	})


	t.Run("nat64", func(t *testing.T) {
		t.Parallel()

		ips := []Line{
			{
				Host: "first.example.com",
				Addr: netip.MustParseAddr("1.1.1.1"),
				ExtraHosts: []string{},
			},


			{
				Host: "second.example.com",
				Addr: netip.MustParseAddr("10.0.0.1"),
				ExtraHosts: []string{},
			},
		}

		ips_check := []Line{
			{
				Host: "first.example.com",
				Addr: netip.MustParseAddr("64:ff9b:1::101:101"),
				ExtraHosts: []string{},
			},


			{
				Host: "second.example.com",
				Addr: netip.MustParseAddr("64:ff9b:1::a00:1"),
				ExtraHosts: []string{},
			},
		}


		var prefixes []netip.Prefix
		prefixes = append(
			prefixes,
			netip.MustParsePrefix("64:ff9b:1::/96"),
		)

		nat64 := toNat64(prefixes, ips)
		fmt.Println(nat64)
		if !reflect.DeepEqual(nat64, ips_check) {
			t.Fail()
		}

	})

}
