.PHONY: help
help: ## Shows this generated help info for Makefile targets
	@grep -E '^[a-zA-Z0-9_-]+:' $(MAKEFILE_LIST) |                       \
	  awk -F: '                                                       \
	  {                                                               \
	    target=$$2;                                                   \
	    if ( !(target in targets) ) {                                 \
	      if ( /:.*##/ ) {                                            \
	        if ( ! /no-help/ ) {                                      \
	          sub(/^.*## ?/,"",$$0);                                  \
	          targets[target] = $$0;                                  \
	        }                                                         \
	      } else {                                                    \
	        targets[target] = ""                                      \
	      }                                                           \
	    }                                                             \
	  }                                                               \
	  END {                                                           \
	    for (target in targets) {                                     \
	      printf "\033[36m%-30s\033[0m %s\n", target, targets[target] \
	    }                                                             \
	  }' | sort

.targets:
	@grep -E '^[a-zA-Z0-9_-]+:' $(MAKEFILE_LIST) | \
	  awk -F: '                                 \
	  {                                         \
	    target=$$2;                             \
	    if ( !(target in targets) ) {           \
	      if ( /:.*##/ ) {                      \
	        if ( ! /no-help/ ) {                \
	          targets[target] = "";             \
	        }                                   \
	      } else {                              \
	        targets[target] = ""                \
	      }                                     \
	    }                                       \
	  }                                         \
	  END {                                     \
	    for (target in targets) {               \
	      printf "%s ", target, targets[target] \
	    }                                       \
	  }'
