% SEAndroid Prolog Engine (Attach Graph)
% Protoype #11
% Feb 13, 2019
% daveti
%
% Support for SWI-prolog
% Support for external attack surface list
% Support for capability list 
% Support for cutoff parameter
%
% NOTE: this is NOT DAG, since there is a cycle
% enabled by bidirectional edges between (n3, n5)
% and (n5, n8)
%
% Query(n1, n5)
% Query(n1, n8)

% Connected(start_node, end_node)
% return true if two nodes are connected
connected(S, S).
connected(S, E) :-
	edge(S, N),
	connected(N, E).
	
% Path(start_node, end_node, path)
% return true if path is a path from S to E
path(S, S, [S]).
path(S, E, [S|P]) :-
	edge(S, N),
	path(N, E, P).

% Query(start_node, end_node)
% return all viable paths between S and E
% NOTE: query could NOT handle loop
query(S, E, Z) :-
	findall(X, path(S, E, X), Z).


% https://www.cpp.edu/~jrfisher/www/prolog_tutorial/2_15.html
connected2(X,Y) :-
	edge(X,Y);
	edge(Y,X).



% So, we need a filter and gprolog does not have a builtin!
% https://stackoverflow.com/questions/297996/prolog-filtering-a-list
filter(_,[],[]).
filter(P,[H|T],[H|T2]) :-
	call(P,H),
	filter(P,T,T2).
filter(P,[_|T],L) :-
	filter(P,T,L).

filter2(_,_,[],[]).
filter2(P,Q,[H|T],[H|T2]) :-
	call(P,H,Q),
	filter2(P,Q,T,T2).
filter2(P,Q,[_|T],L) :-
	filter2(P,Q,T,L).



% Graph traversal
travel(A,B,P,[B|P],_) :-
	edge(A,B).	% NOTE: wildcard queries may still contain cycles within answers.
			% Trying to add membership test before breaks the (n1,_,...) queries
			% although (_,n5,...) queries still work.
			% Feb 10, 2019
travel(A,B,Visited,Path,Cut) :-
	edge(A,C),
	C \== B,
	\+member(C,Visited),
	length(Visited,Len),
	Len < Cut,	% NOTE: cannot wildcard for cutoff in the query
	travel(C,B,[C|Visited],Path,Cut).


is_uniq([]).
is_uniq(L) :-
	length(L,Len1),
	sort(L,S),
	length(S,Len2),
	Len1 == Len2.

path2(A,B,C,Path) :-
	travel(A,B,[A],Q,C),
	is_uniq(Q),	% NOTE: to workaround cycles in wildcard queries
	reverse(Q,Path).

query2(A,B,C,Z) :-
	statistics(walltime, [TimeSinceStart | [TimeSinceLastCall]]),
	findall(X, path2(A,B,C,X), P),
	sort(P,Z),
	length(Z,Len),
	statistics(walltime, [NewTimeSinceStart | [ExecutionTime]]),
	write('Execution took '), write(ExecutionTime), write(' ms'), nl,
	write('Path number '), write(Len), nl.



% DAC: based on different information flow
% NOTE: we assume an edge exists already thus no checking on this
% sub->obj and obj->sub, we have 2 different implementations
% DAC_SUB_OBJ
is_sub(A) :-
	sub_db(all,L),
	member(A,L).

is_obj(A) :-
	obj_db(all,L),
	member(A,L).

is_root(A) :-
	sub(A,U,G,_,_,_,_),
	U==0,
	member(0,G).

is_owner(A,B) :-
	sub(A,U,_,_,_,_,_),
	obj(B,O,_,_,_,_,_),
	U==O.

% Sub->Obj: needs write or execute?
% Since each process is running, we dont need execute here
group_sub_obj_allow(A,B) :-
	sub(A,_,G,_,_,_,_),
	obj(B,_,O,_,P,_,_),
	member(O,G),
	member(P,[4,6,7,3]).	% RWX: 010, 110, 111, 011

other_sub_obj_allow(_,B) :-
	obj(B,_,_,_,_,P,_),
	member(P,[4,6,7,3]).

% Obj->Sub: needs read?
% Q: does the forked process can/need to read the binary file used to create itself?
group_obj_sub_allow(A,B) :-
	sub(B,_,G,_,_,_,_),
	obj(A,_,O,_,P,_,_),
	member(O,G),
	member(P, [4,5,6,7]).	%RWX: 100, 101, 110, 111

other_obj_sub_allow(A,_) :-
	obj(A,_,_,_,_,P,_),
	member(P, [4,5,6,7]).


dac_sub_obj_allow(A,B) :-
	is_root(A);
	is_owner(A,B);
	group_sub_obj_allow(A,B);
	other_sub_obj_allow(A,B).

% Note: there is no short-circuit for logical OR in prolog
% as a result, different paths would be tried, generating
% multiple the same answers. That's why we try to limit
% the usage of OR and use AND if possible by leverage negation
dac_sub_obj_disallow(A,B) :-
	\+is_root(A),
	\+is_owner(A,B),
	\+group_sub_obj_allow(A,B),
	\+other_sub_obj_allow(A,B).

dac_obj_sub_allow(A,B) :-
	is_root(B);
	is_owner(B,A);
	group_obj_sub_allow(A,B);
	other_obj_sub_allow(A,B).

dac_obj_sub_disallow(A,B) :-
	\+is_root(B),
	\+is_owner(B,A),
	\+group_obj_sub_allow(A,B),
	\+other_obj_sub_allow(A,B).

% DAC_SUB_OBJ
dac_sub_obj(A,B) :-
	is_sub(A),
	%dac_sub_obj_allow(A,B).
	\+dac_sub_obj_disallow(A,B).

% DAC_OBJ_SUB
dac_obj_sub(A,B) :-
	is_obj(A),
	%dac_obj_sub_allow(A,B).
	\+dac_obj_sub_disallow(A,B).

dac(A,B) :-
	dac_sub_obj(A,B);
	dac_obj_sub(A,B).

% Add DAC (after edge-based queries)
dac_path([]).
dac_path([_]).
dac_path([H1,H2|T]) :-
	dac(H1,H2),
	dac_path([H2|T]).

% Introduce a worker to update the path
% since the original one passed is immutable
% https://stackoverflow.com/questions/5824802/recursion-in-prolog-on-lists
% NOTE: the sum worker does not work here because we need to go thru each
% element of the list regardless if it is a dac_path or not, and we will only
% add the path into our new list if it is a dac_path!
% So, we need a filter and gprolog does not have a builtin!
% https://stackoverflow.com/questions/297996/prolog-filtering-a-list
% BAD IMPL - DO NOT USE
dac_work([],D,D).
dac_work([H|T],W,D) :-
	dac_path(H),
	dac_work(T,[H|W],D).
% BAD END

%dac_proc([],[]).
%dac_proc([_],[]).
dac_proc(P,Z) :-
	filter(dac_path,P,Z).

path3(A,B,C,Path) :-
	travel(A,B,[A],Q,C),
	is_uniq(Q),	% NOTE: to workaround cycles in wildcard queries
	reverse(Q,Q1),
	dac_path(Q1),
	Path = Q1.

query3(A,B,C,Z) :-
	statistics(walltime, [TimeSinceStart | [TimeSinceLastCall]]),
	findall(X, path3(A,B,C,X), P),	% P contains all viable paths
	sort(P,Z),
	length(Z,Len),
	statistics(walltime, [NewTimeSinceStart | [ExecutionTime]]),
	write('Execution took '), write(ExecutionTime), write(' ms'), nl,
	write('Path number '), write(Len), nl.
	%dac_proc(P,Z).


% Capability layer
% Ideally, we should only need to check the last node of a path
% However, the ending node might not be a sub
% In this case, we need to check the previous
% NOTE: our query do not enforce what ending node should be
% and we do not really care since edges determine
cap_supp(A,C) :-
	sub(A,_,_,_,_,_,L),
	member(C,L).

cap_last([],_).
cap_last(P,C) :-
	last(P,A),
	is_sub(A),
	cap_supp(A,C).

cap_prev([],_).
cap_prev([_],_).
cap_prev(P,C) :-
	length(P,L),
	Prev is L - 1,
	nth1(Prev,P,A),
	is_sub(A),
	cap_supp(A,C).

cap_path([],_).
cap_path(P,C) :-
	cap_last(P,C);
	cap_prev(P,C).

cap_proc(P,C,Z) :-
	filter2(cap_path,C,P,Z).

	
% New query interface
% A: starting node
% B: ending node
% C: cutoff parameter (wildcard not supported)
% D: capability (wildcard exponential) 
% Z: paths (returned)
path4(A,B,C,D,Path) :-
        travel(A,B,[A],Q,C),
        is_uniq(Q),     % NOTE: to workaround cycles in wildcard queries
        reverse(Q,Q1),
        dac_path(Q1),
	cap_path(Q1,D),
        Path = Q1.

query4(A,B,C,D,Z) :-
	statistics(walltime, [TimeSinceStart | [TimeSinceLastCall]]),
	findall(X, path4(A,B,C,D,X), P),	% P contains all viable paths
	sort(P,Z),
	length(Z,Len),
	statistics(walltime, [NewTimeSinceStart | [ExecutionTime]]),
	write('Execution took '), write(ExecutionTime), write(' ms'), nl,
	write('Path number '), write(Len), nl.
	%dac_proc(P,P1),
	%cap_proc(P1,D,Z).




% Support for external attack surface query
ext_supp(O,E) :-
	obj(O,_,_,_,_,_,L),
	member(E,L).

% Only need to check the first element of a given path
ext_path([],_).
ext_path(P,E) :-
	nth1(1,P,S),
	is_obj(S),
	ext_supp(S,E).

ext_proc(P,E,Z) :-
	filter2(ext_path,E,P,Z).


% New query interface
% A: starting node
% B: ending node
% C: cutoff parameter (wildcard not supported)
% D: capability (wildcard exponential)
% E: external attack surface
% Z: paths (returned)
path5(A,B,C,D,E,Path) :-
        travel(A,B,[A],Q,C),
        is_uniq(Q),     % NOTE: to workaround cycles in wildcard queries
        reverse(Q,Q1),
        dac_path(Q1),
        cap_path(Q1,D),
	ext_path(Q1,E),
        Path = Q1.

query5(A,B,C,D,E,Z) :-
	statistics(walltime, [TimeSinceStart | [TimeSinceLastCall]]),
	findall(X, path5(A,B,C,D,E,X), P),	% P contains all viable paths
	sort(P,Z),
	length(Z,Len),
	statistics(walltime, [NewTimeSinceStart | [ExecutionTime]]),
	write('Execution took '), write(ExecutionTime), write(' ms'), nl,
	write('Path number '), write(Len), nl.
	%dac_proc(P,P1),
	%cap_proc(P1,D,P2),
	%ext_proc(P2,E,Z).
	
