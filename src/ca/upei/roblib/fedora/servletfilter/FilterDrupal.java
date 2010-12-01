/*
 *
 *
 * updated libraries to point at new 3.4 libraries and updated imports to org.fcrepo.server.
 * they used to be
 * import fedora.common.Constants;
 * import fedora.server.security.servletfilters.BaseCaching;
 * import fedora.server.security.servletfilters.CacheElement;
 *
 * Legacy filter for use on sites with no fesl authentication.  configured in web.xml
 */

package ca.upei.roblib.fedora.servletfilter;

//import fedora.common.Constants;
import org.fcrepo.common.Constants;
//import fedora.server.security.servletfilters.BaseCaching;
import org.fcrepo.server.security.servletfilters.BaseCaching;
//import fedora.server.security.servletfilters.CacheElement;
import org.fcrepo.server.security.servletfilters.CacheElement;
import java.util.Map;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 *
 * @author ppound
 */
public class FilterDrupal extends BaseCaching
        implements Constants{
    protected static Log log = LogFactory.getLog(FilterDrupal.class);



@Override
    public void destroy() {
        String method = "destroy()";
        if (log.isDebugEnabled()) {
            log.debug(enter(method));
        }
        super.destroy();
        if (log.isDebugEnabled()) {
            log.debug(exit(method));
        }
    }

    @Override
    protected void initThisSubclass(String key, String value) {
         super.initThisSubclass(key,value);
        String method = "initThisSubclass()";
        if (log.isDebugEnabled()) {
            log.debug(enter(method));
        }
       
       //not sure if we need this method or should call super.  seems to work as is
    }

    @Override
    public void populateCacheElement(CacheElement cacheElement, String password) {
        String method = "populateCacheElement()";
        if (log.isDebugEnabled()) {
            log.debug(enter(method));
        }
        Boolean authenticated = null;
        Map namedAttributes = null;
        String errorMessage = null;
        authenticated = Boolean.FALSE;
              

            DrupalUserInfo parser = new DrupalUserInfo();
            if (log.isDebugEnabled()) {
                log.debug("got parser");
            }
            try {
               // parser.findUser(cacheElement.getUserid(), password);
                parser.findUser(cacheElement.getUserid(),password);
                if (log.isDebugEnabled()) {
                    log.debug("back from databaseQuery");
                }
           
            } catch (Throwable th) {
                String msg = "error quering database";
               //showThrowable(th, log, msg);
                log.error(msg);
                //throw new IOException(msg);
            }
            authenticated = parser.getAuthenticated();
            namedAttributes = parser.getNamedAttributes();
       
        if (log.isDebugEnabled()) {
            log.debug(format(method, null, "authenticated"));
            log.debug(authenticated);
            log.debug(format(method, null, "namedAttributes"));
            log.debug(namedAttributes);
            log.debug(format(method, null, "errorMessage", errorMessage));
        }
        cacheElement.populate(authenticated,
                              null,
                             namedAttributes,
                              errorMessage);
        if (log.isDebugEnabled()) {
            log.debug(exit(method));
        }
    }
    
  /*  public static void main(String args[]){
        
        FilterDrupal fd = new FilterDrupal();
        fd.populateCacheElement(null,null);
    }*/
}
