:- initialization(main, main).

main(Argv) :-
	nth0(0, Argv, Start),
	nth0(1, Argv, End),
	nth0(2, Argv, Cutoff),
	nth0(3, Argv, Cap),
	atom_number(Cutoff, CutoffN),
	read_term_from_atom(Cap, CapT, []),
	read_term_from_atom(Start, StartT, []),
	read_term_from_atom(End, EndT, []),
	query4(StartT, EndT, CutoffN, CapT, Z),
	print(Z).
