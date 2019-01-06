% SEAndroid Prolog Engine (Attach Graph)
% Protoype #1
% Jan 10, 2019
% daveti
%
% n1->n2->n3
%     |   |
%     v   v
%     n4->n5

% Edge(start_node, end_node)
edge(n1, n2).
edge(n2, n3).
edge(n2, n4).
edge(n4, n5).
edge(n3, n5).

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
query(S, E, Z) :-
	findall(X, path(S, E, X), Z).
