% SEAndroid Prolog Engine (Attach Graph)
% Protoype #8
% Feb 8, 2019
% daveti
%
% Support for cutoff parameter
%
% NOTE: this is NOT DAG, since there is a cycle
% enabled by bidirectional edges between (n3, n5)
% and (n5, n8)
%
% Query(n1, n5)
% Query(n1, n8)
%
% n1->n2->n3->n6->n7->n8
%     |   A       A
%     v   v       |
%     n4->n5<------

% sub/obj(node, uid, gid, user, group, other)
% GID for process is a list supporting a group of GIDs
sub(n1, 1, [1], 7, 7, 7).
sub(n3, 1, [1], 7, 7, 7).
sub(n4, 1, [1], 7, 7, 7).
sub(n7, 1, [1], 7, 7, 7).
sub_db(all, [n1,n3,n4,n7]).

obj(n2, 1, 1, 7, 7, 7).
obj(n5, 1, 1, 7, 7, 7).
obj(n6, 1, 1, 7, 7, 7).
obj(n8, 2, 2, 4, 4, 4).	% Others can read
%obj(n8, 2, 2, 4, 4, 0).	% Others cannot read
obj_db(all, [n2,n5,n6,n8]).



% Edge(start_node, end_node)
edge(n1, n2).
edge(n2, n3).
edge(n2, n4).
edge(n4, n5).
edge(n3, n5).
edge(n3, n6).
edge(n6, n7).
edge(n5, n7).
edge(n7, n8).
edge(n7, n5).
edge(n5, n3).

% Self edges
edge(n5, n5).
edge(n8, n8).

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
	sub(A,U,G,_,_,_),
	U==0,
	member(0,G).

is_owner(A,B) :-
	sub(A,U,_,_,_,_),
	obj(B,O,_,_,_,_),
	U==O.

% Sub->Obj: needs write or execute?
group_sub_obj_allow(A,B) :-
	sub(A,_,G,_,_,_),
	obj(B,_,O,_,P,_),
	member(O,G),
	member(P,[4,6,7,3,1]).	% RWX: 010, 110, 111, 011, 001

other_sub_obj_allow(_,B) :-
	obj(B,_,_,_,_,P),
	member(P,[4,6,7,3,1]).

% Obj->Sub: needs read?
% Q: does the forked process can/need to read the binary file used to create itself?
group_obj_sub_allow(A,B) :-
	sub(B,_,G,_,_,_),
	obj(A,_,O,_,P,_),
	member(O,G),
	member(P, [4,5,6,7]).	%RWX: 100, 101, 110, 111

other_obj_sub_allow(A,_) :-
	obj(A,_,_,_,_,P),
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


% Graph traversal
travel(A,B,P,[B|P],_) :- 
	edge(A,B).
travel(A,B,Visited,Path,Cut) :-
	edge(A,C),
	C \== B,
	\+member(C,Visited),
	length(Visited,Len),
	Len < Cut,
	travel(C,B,[C|Visited],Path,Cut).

path2(A,B,C,Path) :-
	travel(A,B,[A],Q,C), 
	reverse(Q,Path).

query2(A,B,C,Z) :-
	findall(X, path2(A,B,C,X), Z).


% Add DAC (after edge-based queries)
dac_path([]).
dac_path([_]).
dac_path([H1,H2|T]) :-
	dac(H1,H2),
	dac_path([H2|T]).

% Introduce a worker to update the path
% since the original one passed is immutable
dac_work([],D,D).
dac_work([H|T],W,D) :-
	dac_path(H),
	dac_work(T,[H|W],D).

dac_proc([],[]).
dac_proc([_],[]).
dac_proc(P,D) :-
	dac_work(P,[],D).

query3(A,B,C,Z) :-
	findall(X, path2(A,B,C,X), P),	% P contains all viable paths
	dac_proc(P,Z).
	


