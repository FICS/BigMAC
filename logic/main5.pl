:- initialization(main, main).

main(Argv) :-
	nth0(0, Argv, Start),
	nth0(1, Argv, End),
	nth0(2, Argv, Cutoff),
	nth0(3, Argv, Cap),
	nth0(4, Argv, Ext),
	atom_number(Cutoff, CutoffN),
	read_term_from_atom(Cap, CapT, []),
	read_term_from_atom(Ext, ExtT, []),
	read_term_from_atom(Start, StartT, []),
	read_term_from_atom(End, EndT, []),
	query5(StartT, EndT, CutoffN, CapT, ExtT, Z),
	print(Z).
