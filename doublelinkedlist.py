class _DoublyLinkedBase:  
    """A base class providing a doubly linked list representation."""  
    class _Node:  
        """Lightweight, nonpublic class for storing a doubly linked node."""  
        slots = _element , _prev , _next            # streamline memory  
        def __init__(self, element, prev, next):   # initialize node's fields  
            self._element = element                #user's element  
            self._prev = prev                      # previous node reference  
            self._next = next                      # next node reference  
  
    def __init__(self):  
        """Create an empty list."""  
        self._header = self._Node(None, None, None)  
        self._trailer = self._Node(None, None, None)  
        self._header._next = self._trailer           # trailer is after header  
        self._trailer. prev = self._header           # header is before trailer  
        self._size = 0                               # number of elements  
  
    def __len__(self):  
        """Return the number of elements in the list."""  
        return self._size  
  
    def is_empty(self):  
        """Return True if list is empty."""  
        return self._size == 0  
  
    def _insert_between(self, e, predecessor, successor):  
        """Add element e between two existing nodes and return new node."""  
        newest = self._Node(e, predecessor, successor) # linked to neighbors  
        predecessor._next = newest  
        successor._prev = newest  
        self._size += 1  
        return newest  
  
    def _delete_node(self, node):  
        """Delete nonsentinel node from the list and return its element."""  
        predecessor = node._prev  
        successor = node._next  
        predecessor._next = successor  
        successor._prev = predecessor  
        self._size −= 1  
        element = node._element                                 # record deleted element  
        node._prev = node._next = node._element = None          # deprecate node  
        return element                                          # return deleted element  
      
class LinkedDeque(_DoublyLinkedBase):                           #note the use of inheritance  
    """Double-ended queue implementation based on a doubly linked list."""  
      
    def first(self):  
        """Return (but do not remove) the element at the front of the deque."""  
        if self.is_empty():  
            raise Empty("Deque is empty")  
        return self._header._next._element        #real item just after header  
      
    def last(self):  
        """Retrun (but do not remove) the element at the back of the deque."""  
        if self.is_empty():  
            raise Empty("Deque is empty")  
        return self._trailer._prev._element       #real item just before trailer  
      
    def insert_first(self,e):  
        """Add an element to the front of the deque."""  
        self._insert_between(e, self._header, self._header._next)  #after header  
          
    def insert_last(self,e):  
        """Add an element to the back of the deque. 
        Raise Empty exception if the deque is empty. 
        """  
          
        if self.is_empty():  
            rasie Empty("Deque is empty")  
        return self._delete_node(self._trailer._prev)   #use inherited method  
          
class PosintionalList(_DoublyLinkedBase):  
    """A sequential container of elements allowing positional access."""  
    #---------- nested Position class ------------------------  
    class Position:  
        """An abstraction representing the location of a single element."""  
          
        def __init__(self, container, node):  
            """Constructor should not be invoked by user."""  
            self._container = container  
            self._node = node  
              
        def elemnt(self):  
            """Return the element stored at this Positiong."""  
            return self._node._element  
          
        def __eq__(self, other):  
            """Return True if other is a Position representing the same location."""  
            return type(other) is type(self) and other._node is self._node  
          
        def __ne__(self, other):  
            """Return True is other does not represent the same location."""  
            return not (self == other)   #opposite of __eq__  
          
        #---------- utility method ------------------  
        def _validate(self,p):  
            """Return position's node, or raise approriate error if invalid."""  
            if not isinstace(p, self.Position):  
                raise TypeError('p must be proper Position type')  
            if p._container is not self:  
                raise ValueError('p does not belong to this container')  
            if p._node._next is None:         #convention for deprecated nodes  
                raise ValueError('p is no longer valid')  
            return p._node  
          
        def _make_position(self, node):  
            """Return Position instance for given node(or None if sentinel)."""  
            if node if self._header or node is self._trailer:  
                return None                           #boundary violation  
            else:  
                return self.Position(self, node)      #legitimate position  
          
        #----------- accessors ----------------------  
        def first(self):  
            """Return the first Position in the list(or None if list ie empty)."""  
            return self._make_position(self._header._next)  
          
        def last(self):  
            """Return the last Position in the list(or None if list is empty)."""  
            return self._make_postion(self.trailer._prev)  
          
        def before(self,p):  
            """Return the Position just before Position p (or None if p is first)."""  
            node == self._validate(p)  
            return self._make_position(node._prev)  
          
        def after(self, p):  
            """Return the Position just after Position p (or None if p is last)."""  
            node = self._validate(p)  
            return self._make_position(node._next)  
          
        def __iter__(self):  
            """Generate a forward iteration of the elements of the list."""  
            cursor = self.first()  
            while cursor is not None:  
                yield cursor.element()  
                cursor = self.after(cursor)  
                  
        #---------- mutators --------------------------------  
        # override inherited version to return Position, rather than Node  
        def _insert_between(self,e,predecessor, successor):  
            """Add element between existing nodes and return new Position."""  
            node = super()._insert_between(e, predecessor, successor)  
            return self._make_positiong(node)  
          
        def add_first(self,e):  
            """Insert element e at the front of the list and return new Position."""  
            return self._insert_between(e, self._header, self._header._next)  
          
        def add_last(self, e):  
            """Insert element e at the back of the list and return new Position."""  
            return self._insert_between(e,self._trailer._prev,self._trailer)  
          
        def add_before(self, p, e):  
            """Insert element e into list before Position p and return new Position."""  
            original = self._validate(p)  
            return self._insert_between(e,original._prev, original)  
          
        def add_after(self,e):  
            """Insert element e into list after Position p and return new Position."""  
            original = self._validate(p)  
            return self._insert_between(e,original, origiane._next)  
          
        def delete(self, p):  
            """Remove and return the element at Position p."""  
            original = self._validate(p)  
            return self._delete_node(original) #inherited method returns element  
          
        def replace(self,p,e):  
            """Replace the element at Position p with e. 
            Return the element formerly at Positin p. 
            """  
            original = self._validate(p)  
            old_value = original._element      #temporary store old element  
            original._element = e              #replace with new element  
            return old_value                   #return the old element value  
