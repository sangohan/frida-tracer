import csv
import collections
import bisect
import sys

class Module:
	def __init__(self, address, size, name):
		self.address = address
		self.size = size
		self.name = name
	def __repr__(self):
		return "(%d, %d, %s)" % (self.address, self.size, self.name)

class Export:
	def __init__(self, module, name, address):
		self.module = module
		self.name = name
		self.address = address
	def __repr__(self):
		return "(%s,%s,%d)" % (self.module, self.name, self.address)

class SymbolTable:
	def __init__(self, filename):
		d = []
		with open(filename, 'r') as f:
			for row in csv.reader(f):
				d.append(Module(int(row[1], 16), int(row[2]), row[0]))
		d.sort(lambda x, y: x.address - y.address)
		self._modules = d
		self._indices = [ m.address for m in d ]

	def lookup(self, addr):
		idx = bisect.bisect(self._indices, addr)
		if idx == 0:
			return None
		m = self._modules[idx - 1]
		if addr >= m.address + m.size:
			return None
		return m

class SuperSymbolTable:
	def __init__(self, filename):
		self._exports = {}
		with open(filename, 'r') as f:
			for row in csv.reader(f):
				addr = int(row[2], 16)
				self._exports[addr] = Export(row[0], row[1], addr)

	def lookup(self, addr):
		return self._exports.get(addr, None)

mt = SymbolTable('modules.csv')
et = SuperSymbolTable('exports.csv')

heatmap = {}

with open("events.csv") as events:
	for row in csv.reader(events):
		location = int(row[0], 16)
		target = int(row[1], 16)
		depth = int(row[2])
		e = et.lookup(target)
		m = mt.lookup(target)
		if m:
			mod = heatmap.get(m.name, {})
			heatmap[m.name] = mod
			mod[target] = mod.get(target, 0) + 1

for x in heatmap.keys():
	print x,"=[", len(heatmap[x]), "]"
	for y in sorted(heatmap[x].items(), key=lambda x: x[1], reverse=True):
		print "  ", et.lookup(y[0]) or hex(y[0]), y[1]
