:- initialization(main, main).

main(Argv) :-
	nth0(0, Argv, Start),
	nth0(1, Argv, End),
	nth0(2, Argv, Cutoff),
	%nth0(3, Argv, Cap),
	%nth0(4, Argv, Ext),
	atom_number(Cutoff, CutoffN),
	query3(Start, End, CutoffN, Z),
	print(Z).
	%read_term_from_atom(Cap, CapT, []),
	%read_term_from_atom(Ext, ExtT, []),
	%query5(Start, End, CutoffN, CapT, ExtT, Z),
